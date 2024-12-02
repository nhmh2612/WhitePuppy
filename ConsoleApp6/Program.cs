using System;
using SharpPcap;
using PacketDotNet;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Data.SQLite;

class Program
{
    // Biến toàn cục
    static string ipFilter = null;
    static long totalBytes = 0;
    static DateTime captureStartTime = DateTime.MinValue;
    static bool isCapturing = true;
    static HashSet<int> suspiciousPorts = new HashSet<int> { 23, 445, 3389 }; // Telnet, SMB, RDP
    static HashSet<string> suspiciousIPs = new HashSet<string> { "192.168.1.100" };

    static void Main(string[] args)
    {
        try
        {
            // Khởi tạo cơ sở dữ liệu
            InitializeDatabase();

            // Lấy danh sách các thiết bị mạng
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("Không tìm thấy thiết bị nào.");
                return;
            }

            // Hiển thị danh sách các thiết bị mạng
            Console.WriteLine("Fix_V0.2");
            Console.WriteLine("Danh sách thiết bị mạng:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            // Yêu cầu người dùng chọn thiết bị hợp lệ
            int deviceIndex;
            do
            {
                Console.WriteLine("Chọn thiết bị (nhập số): ");
            } while (!int.TryParse(Console.ReadLine(), out deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count);

            var device = devices[deviceIndex];

            // Hỏi người dùng địa chỉ IP cần lọc
            Console.WriteLine("Nhập địa chỉ IP muốn lọc (nhập để bỏ qua): ");
            ipFilter = Console.ReadLine();

            // Đăng ký sự kiện khi có gói tin mới
            device.OnPacketArrival += Device_OnPacketArrival;

            // Mở thiết bị để bắt gói tin
            device.Open(DeviceModes.Promiscuous);
            Console.WriteLine("Bắt gói tin (nhấn 'P' để tạm dừng/tiếp tục, Enter để dừng hẳn)");

            // Khởi tạo thời gian bắt đầu
            captureStartTime = DateTime.Now;

            // Thực hiện bắt gói tin
            device.StartCapture();

            // Xử lý phím bấm
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.P)
                {
                    isCapturing = !isCapturing;
                    Console.WriteLine(isCapturing ? "Tiếp tục bắt gói tin" : "Tạm dừng bắt gói tin");
                }
            } while (key.Key != ConsoleKey.Enter);

            // Dừng bắt và đóng thiết bị
            device.StopCapture();
            device.Close();

            Console.WriteLine("\nĐã dừng bắt gói tin.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi: {ex.Message}");
        }
    }

    // Xử lý khi có gói tin
    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        if (!isCapturing) return;

        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            // Khởi tạo các biến gói tin ban đầu là null
            IPv4Packet ipPacket = null;
            IPv6Packet ipv6Packet = null;
            TcpPacket tcpPacket = null;
            UdpPacket udpPacket = null;

            // Xử lý gói tin IPv4
            ipPacket = packet.Extract<IPv4Packet>();
            if (ipPacket != null && !string.IsNullOrEmpty(ipFilter) &&
                ipPacket.SourceAddress.ToString() != ipFilter &&
                ipPacket.DestinationAddress.ToString() != ipFilter)
            {
                return;
            }

            if (ipPacket != null)
            {
                Console.WriteLine($"\nIPv4: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
                SavePacketToDatabase("IPv4", ipPacket.SourceAddress.ToString(), ipPacket.DestinationAddress.ToString(), null);
            }

            // Xử lý gói tin IPv6
            ipv6Packet = packet.Extract<IPv6Packet>();
            if (ipv6Packet != null)
            {
                Console.WriteLine($"\nIPv6: {ipv6Packet.SourceAddress} -> {ipv6Packet.DestinationAddress}");
                SavePacketToDatabase("IPv6", ipv6Packet.SourceAddress.ToString(), ipv6Packet.DestinationAddress.ToString(), null);
            }

            // Xử lý gói tin TCP
            tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                Console.WriteLine($"TCP: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");
                PrintPayload(tcpPacket.PayloadData, "TCP");

                if (suspiciousPorts.Contains(tcpPacket.DestinationPort))
                {
                    Console.WriteLine($"Cảnh báo: Gói tin đáng ngờ tới cổng {tcpPacket.DestinationPort}");
                }

                SavePacketToDatabase("TCP", tcpPacket.SourcePort.ToString(), tcpPacket.DestinationPort.ToString(), BitConverter.ToString(tcpPacket.PayloadData));
            }

            // Xử lý gói tin UDP
            udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                Console.WriteLine($"UDP: {udpPacket.SourcePort} -> {udpPacket.DestinationPort}");
                PrintPayload(udpPacket.PayloadData, "UDP");

                SavePacketToDatabase("UDP", udpPacket.SourcePort.ToString(), udpPacket.DestinationPort.ToString(), BitConverter.ToString(udpPacket.PayloadData));
            }

            // Tính toán băng thông
            totalBytes += rawPacket.Data.Length;
            TimeSpan captureDuration = DateTime.Now - captureStartTime;
            double bandwidth = (totalBytes * 8) / captureDuration.TotalSeconds / 1000; // Kbps
            Console.WriteLine($"Băng thông hiện tại: {bandwidth:F2} Kbps");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi xử lý gói tin: {ex.Message}");
        }
    }

    // Hiển thị nội dung gói tin
    private static void PrintPayload(byte[] payload, string protocol)
    {
        if (payload != null && payload.Length > 0)
        {
            int maxLength = Math.Min(payload.Length, 50);
            string payloadData = BitConverter.ToString(payload, 0, maxLength);
            Console.WriteLine($"Nội dung {protocol}: {payloadData}" + (payload.Length > maxLength ? "..." : ""));
        }
    }

    // Khởi tạo cơ sở dữ liệu SQLite
    private static void InitializeDatabase()
    {
        using (var connection = new SQLiteConnection("Data Source=PacketLog.db"))
        {
            connection.Open();
            string createTableQuery = @"
                CREATE TABLE IF NOT EXISTS Packets (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Protocol TEXT,
                    Source TEXT,
                    Destination TEXT,
                    Payload TEXT,
                    Timestamp DATETIME
                )";
            using (var command = new SQLiteCommand(createTableQuery, connection))
            {
                command.ExecuteNonQuery();
            }
        }
    }

    // Lưu gói tin vào cơ sở dữ liệu SQLite
    private static void SavePacketToDatabase(string protocol, string source, string destination, string payload)
    {
        using (var connection = new SQLiteConnection("Data Source=PacketLog.db"))
        {
            connection.Open();
            string insertQuery = @"
                INSERT INTO Packets (Protocol, Source, Destination, Payload, Timestamp)
                VALUES (@Protocol, @Source, @Destination, @Payload, @Timestamp)";
            using (var command = new SQLiteCommand(insertQuery, connection))
            {
                command.Parameters.AddWithValue("@Protocol", protocol);
                command.Parameters.AddWithValue("@Source", source);
                command.Parameters.AddWithValue("@Destination", destination);
                command.Parameters.AddWithValue("@Payload", payload);
                command.Parameters.AddWithValue("@Timestamp", DateTime.Now);
                command.ExecuteNonQuery();
            }
        }
    }
}
