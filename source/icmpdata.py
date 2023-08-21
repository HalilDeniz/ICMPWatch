import sqlite3

class ICMPDatabase:
    def __init__(self, dbname="icmpdata.db"):
        self.conn = sqlite3.connect(dbname)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS icmp_packets
                (timestamp TEXT, 
                src_ip TEXT, 
                dst_ip TEXT, 
                src_mac TEXT, 
                dst_mac TEXT, 
                ip_version TEXT, 
                ttl TEXT,
                icmp_checksum TEXT, 
                packet_size TEXT, 
                icmp_type_str TEXT, 
                icmp_echo_identifier TEXT, 
                icmp_echo_sequence TEXT,
                payload_hex TEXT, 
                payload_content TEXT)''')
        self.conn.commit()

    def insert_packet(self, packet_data):
        query = '''INSERT INTO icmp_packets (timestamp, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, icmp_checksum, 
                   packet_size, icmp_type_str, icmp_echo_identifier, icmp_echo_sequence, payload_hex, payload_content)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
        self.cursor.execute(query, packet_data)
        self.conn.commit()

    def fetch_all_packets(self):
        self.cursor.execute("SELECT * FROM icmp_packets")
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()
