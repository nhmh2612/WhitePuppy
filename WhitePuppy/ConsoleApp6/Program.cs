using System;
using SharpPcap;
using PacketDotNet;

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
            Console.WriteLine("Danh sach thiet bi mang:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            // Vòng lặp yêu cầu người dùng chọn thiết bị hợp lệ
            int deviceIndex = -1;
            while (deviceIndex < 0 || deviceIndex >= devices.Count)
            {
                Console.Write("Chon thiet bi (nhap so): ");
                string input = Console.ReadLine() ?? string.Empty;
                if (!int.TryParse(input, out deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count)
                {
                    Console.WriteLine("Chon thiet bi khong hop le. Vui long thu lai.");
                    deviceIndex = -1; // Reset lại nếu nhập không hợp lệ
                }
            }

            var device = devices[deviceIndex];

            // Đăng ký sự kiện khi có gói tin mới
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            // Mở thiết bị để bắt gói tin
            device.Open(DeviceModes.Promiscuous);
            Console.WriteLine("Bat goi tin (Enter de dung lai)");

            // Bắt gói tin
            device.StartCapture();

            // Chờ người dùng nhấn ENter để dừng
            Console.ReadLine();

            // Dừng bắt gói tin và đóng thiết bị
            device.StopCapture();
            device.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Loi: {ex.Message}");
        }
    }

    // Xử lý khi có gói tin đến
    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            // Lấy dữ liệu thô của gói tin từ sự kiện
            var rawPacket = e.GetPacket();//Bao gồm tất cả dữ liệu bắt được

            // Phân tích gói tin với kiểu link layer và dữ liệu gói tin
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
               //ParsePacket(): Để phân tích dữ liệu gói tin thô -> phân tích để tạo ra các 'Packet',(packet bao gồm IP, UDP, TCP,...)

            // Trích xuất gói tin IPv4
            var ipPacket = packet.Extract<IPv4Packet>();

            if (ipPacket != null)
            {
                try
                {
                    // Lấy địa chỉ IP nơi gửi và nơi nhận
                    var srcIp = ipPacket.SourceAddress.ToString();
                    var dstIp = ipPacket.DestinationAddress.ToString();

                    //Nhớ thêm $ và {cái gì đó} để truyền dữ liệu vào
                    Console.WriteLine($"\nIP: {srcIp} -> {dstIp}");
                    Console.WriteLine($"Noi gui: {srcIp}");
                    Console.WriteLine($"Noi nhan: {dstIp}");

                }
                catch (Exception ex )
                {
                    Console.WriteLine("Loi IPV4.94: ",ex.Message);
                }
            }
            else 
            {
                //Xuất để kiểm tra coi có lỗi không :))
                Console.WriteLine($"Day khong phai la IPV4");
            }


            // Trích xuất và xử lý gói tin TCP
            var tcpPacket = packet.Extract<TcpPacket>(); //Nội dung chưa được mã hóa

            if (tcpPacket != null)
            {               
                //Hiện thị cổng nguồn và cổng đích
                Console.WriteLine($"Goi tin TCP: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");

                //Hiện thị và hiển thị dữ liệu gói tin lên payload
                var payload = tcpPacket.PayloadData;
                if (payload != null && payload.Length > 0)
                {
                    //BitConverter: chuyển đổi mảng payload thành chuỗi các giá trị thập lục phân
                    Console.WriteLine($"Noi dung: {BitConverter.ToString(payload)}");
                }
                else
                {
                    Console.WriteLine("Khong co noi dung TCP.");
                }
            }
            else
            {
                //Xuất để kiểm tra coi có lỗi không :))
                Console.WriteLine("Chuc mung loi roi TCP.127");
            }
            //Nội dung chưa được mã hóa
            // Trích xuất và xử lý gói tin UDP
            var udpPacket = packet.Extract<UdpPacket>();

            if (udpPacket != null)
            {
                Console.WriteLine($"Goi tin UDP: {udpPacket.SourcePort} -> {udpPacket.DestinationPort}");

                var payload = udpPacket.PayloadData;
                if (payload != null && payload.Length > 0)
                {
                    Console.WriteLine($"Noi dung: {BitConverter.ToString(payload)}");
                }
                else
                {
                    Console.WriteLine("Neu co cai nay xuat hien loi 100% UDP.1144.");
                }
            }
            else
            {
                //Xuất để kiểm tra coi có lỗi không :))
                Console.WriteLine("Chuc mung loi roi UPD.150");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Loi xu ly goi tin: {ex.Message}");
        }
    }
}
