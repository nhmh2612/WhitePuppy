using System;
using SharpPcap;
using PacketDotNet;
using System.Globalization;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            // Lấy danh sách các thiết bị mạng
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("Khong tim thay thiet bi nao.");
                return;
            }

            // Hiển thị danh sách các thiết bị mạng
            Console.WriteLine("Fix_V0.2");
            Console.WriteLine("Danh sach thiet bi mang:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            // Yêu cầu người dùng chọn thiết bị hợp lệ
            int deviceIndex;
            do
            {
                Console.WriteLine("Chon thiet bi (nhap so): ");
            } while (!int.TryParse(Console.ReadLine(), out deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count);

            var device = devices[deviceIndex];

            // Đăng ký sự kiện khi có gói tin mới
            device.OnPacketArrival += Device_OnPacketArrival;

            // Mở thiết bị để bắt gói tin
            device.Open(DeviceModes.Promiscuous);
            Console.WriteLine("Bat goi tin (Enter de dung lai)");

            // Thực hiện bắt gói tin
            device.StartCapture();

            // Dừng khi nhấn Enter
            Console.ReadLine();

            // Dừng bắt và đóng thiết bị
            device.StopCapture();
            device.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Loi: {ex.Message}");
        }
    }

    // Xử lý khi có gói tin
    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            // Khởi tạo các biến gói tin ban đầu là null
            IPv4Packet ipPacket = null;
            IPv6Packet ipv6Packet = null;
            IcmpV4Packet icmpPacket = null;
            TcpPacket tcpPacket = null;
            UdpPacket udpPacket = null;

            // Xử lý gói tin IPv4
            ipPacket = packet.Extract<IPv4Packet>();
            if (ipPacket != null)
            {
                Console.WriteLine($"\nIPv4: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
            }

            // Xử lý gói tin IPv6
            ipv6Packet = packet.Extract<IPv6Packet>();
            if (ipv6Packet != null)
            {
                Console.WriteLine($"\nIPv6: {ipv6Packet.SourceAddress} -> {ipv6Packet.DestinationAddress}");
            }

            // Xử lý gói tin ICMP
            icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                Console.WriteLine($"\nICMP: Type {icmpPacket.TypeCode}");
            }

            // Xử lý gói tin TCP
            tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                Console.WriteLine($"TCP: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");
                PrintPayload(tcpPacket.PayloadData, "TCP");
            }

            // Xử lý gói tin UDP
            udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                Console.WriteLine   ($"UDP: {udpPacket.SourcePort} -> {udpPacket.DestinationPort}");
                PrintPayload(udpPacket.PayloadData, "UDP");
            }

            // kiểm tra nếu có gói tin nào đó chưa xử lý
            if (ipPacket == null && ipv6Packet == null && icmpPacket == null && tcpPacket == null && udpPacket == null)
            {
                Console.WriteLine("Goi tin khong xac dinh hoac khong duoc ho tro.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Loi xu ly goi tin: {ex.Message}");
        }
    }

    // Hiển thị nội dung gói tin với giới hạn byte
    private static void PrintPayload(byte[] payload, string protocol)
    {
        if (payload != null && payload.Length > 0)
        {
            int maxLength = Math.Min(payload.Length, 50);
            string payloadData = BitConverter.ToString(payload, 0, maxLength);
           Console.WriteLine($"Noi dung {protocol}: {payloadData}" + (payload.Length > maxLength ? "..." : ""));
        }
    }

    // Hàm hỗ trợ viết chuỗi không dấu
    private static string RemoveDiacritics(string text)
    {
        var normalizedString = text.Normalize(NormalizationForm.FormD);
        var stringBuilder = new StringBuilder();

        foreach (var c in normalizedString)
        {
            var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
            if (unicodeCategory != UnicodeCategory.NonSpacingMark)
            {
                stringBuilder.Append(c);
            }
        }

        return stringBuilder.ToString().Normalize(NormalizationForm.FormC);
    }
}
