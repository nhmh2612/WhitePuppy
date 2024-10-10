using System;
using SharpPcap;
using PacketDotNet;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            // Lay danh sach cac thiet bi mang
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("Khong tim thay thiet bi nao.");
                return;
            }

            // Hien thi danh sach cac thiet bi mang
            Console.WriteLine("Fix_V0.2");
            Console.WriteLine("Danh sach thiet bi mang:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            // Yeu cau nguoi dung chon thiet bi hop le
            int deviceIndex = -1;
            do
            {
                Console.Write("Chon thiet bi (nhap so): ");
            } while (!int.TryParse(Console.ReadLine(), out deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count);

            var device = devices[deviceIndex];

            // Dang ky su kien khi co goi tin moi
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            // Mo thiet bi de bat goi tin
            device.Open(DeviceModes.Promiscuous);
            Console.WriteLine("Bat goi tin (Enter de dung lai)");

            // Bat goi tin
            device.StartCapture();

            // Cho nguoi dung nhan Enter de dung
            Console.ReadLine();

            // Dung bat goi tin va dong thiet bi
            device.StopCapture();
            device.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Loi: {ex.Message}");
        }
    }

    // Xu ly khi co goi tin den
    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            // Lay du lieu tho cua goi tin tu su kien
            var rawPacket = e.GetPacket();

            // Phan tich goi tin voi kieu link layer va du lieu goi tin
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            // Xu ly goi tin IPv4
            var ipPacket = packet.Extract<IPv4Packet>();
            if (ipPacket != null)
            {
                Console.WriteLine($"\nIPv4: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
            }

            // Xu ly goi tin IPv6
            var ipv6Packet = packet.Extract<IPv6Packet>();
            if (ipv6Packet != null)
            {
                Console.WriteLine($"\nIPv6: {ipv6Packet.SourceAddress} -> {ipv6Packet.DestinationAddress}");
            }

            // Xu ly goi tin ICMP
            var icmpPacket = packet.Extract<IcmpV4Packet>();
            if (icmpPacket != null)
            {
                Console.WriteLine($"\nICMP: Type {icmpPacket.TypeCode}");
            }

            // Xu ly goi tin TCP
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                Console.WriteLine($"TCP: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");
                var payload = tcpPacket.PayloadData;
                if (payload != null && payload.Length > 0)
                {
                    // Gioi han so luong byte hien thi trong payload (toi da 50 byte)
                    int maxLength = Math.Min(payload.Length, 50);
                    Console.WriteLine($"Noi dung TCP: {BitConverter.ToString(payload, 0, maxLength)}" +
                                      (payload.Length > maxLength ? "..." : ""));
                }
            }

            // Xu ly goi tin UDP
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                Console.WriteLine($"UDP: {udpPacket.SourcePort} -> {udpPacket.DestinationPort}");
                var payload = udpPacket.PayloadData;
                if (payload != null && payload.Length > 0)
                {
                    // Gioi han so luong byte hien thi trong payload (toi da 50 byte)
                    int maxLength = Math.Min(payload.Length, 50);
                    Console.WriteLine($"Noi dung UDP: {BitConverter.ToString(payload, 0, maxLength)}" +
                                      (payload.Length > maxLength ? "..." : ""));
                }
            }

            // Kiem tra neu khong phai cac goi tin pho bien
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
}
