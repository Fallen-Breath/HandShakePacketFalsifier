import json
import select
import struct
import threading
from io import BytesIO
from socket import socket


CONFIG_FILE = 'config.json'
HAND_SHAKE_PACKET_ID = 0x00


def forward(source: socket, target: socket):
	while True:
		data = source.recv(1024)
		if not data:
			break
		target.sendall(data)


class Address:
	def __init__(self, data):
		"""
		:param data: a dict with format {address: 'xxx', port: 123}
		"""
		self.address = data['hostname']
		self.port = data['port']

	def to_tuple(self):
		return self.address, self.port

	def __str__(self):
		return '{}:{}'.format(self.address, self.port)


class Config:
	def __init__(self, config_file):
		with open(config_file) as file_handler:
			data = json.load(file_handler)
		self.listen_addr = Address(data['listen'])
		self.target_addr = Address(data['target'])
		self.fake_addr = Address(data['fake'])
		print('Listen Address:', self.listen_addr)
		print('Target Address:', self.target_addr)
		print('Fake Address:', self.fake_addr)


class ConnectionForwarder:
	def __init__(self, config_file):
		self.config = Config(config_file)

	def run(self):
		sock = socket()
		listen_addr = self.config.listen_addr
		sock.bind(listen_addr.to_tuple())
		print('blind', listen_addr)
		try:
			sock.listen(5)
			while True:
				conn, addr = sock.accept()
				print('New connection from {}:{}'.format(*addr))
				connection = Connection(self, conn)
				connection.start()
		finally:
			sock.close()


class Connection(threading.Thread):
	id_counter = 0

	def __init__(self, forwarder, conn):
		super().__init__()
		self.setDaemon(True)
		self.forwarder = forwarder
		self.conn = conn  # type: socket
		self.target_sock = socket()
		self.closed = False
		self.cid = self.id_counter
		Connection.id_counter += 1

	def log(self, *args):
		print('[Connection{}]'.format(self.cid), *args)

	def run(self):
		self.target_sock.connect(self.forwarder.config.target_addr.to_tuple())
		pipe_backwards = Pipe(self, self.target_sock, self.conn)
		pipe_backwards.start()  # target -> conn

		# conn -> target, needs filtering

		convert_success = False
		try:
			stream = self.conn.makefile('rb', 0)
			while not convert_success and not self.closed:
				ready_to_read = select.select([stream], [], [], 0.05)[0]
				if not ready_to_read:
					continue

				length_data = BytesIO()
				length = VarInt.read(stream, length_data)

				if length_data.getvalue() == b'\xfe\x01':  # Legacy Server List Ping
					self.log('Legacy Server List Ping')
					self.target_sock.sendall(length_data.getvalue())
					continue

				packet_in = BytesIO()
				packet_in.write(stream.read(length))
				# Ensure we read all the packet
				while len(packet_in.getvalue()) < length:
					packet_in.write(stream.read(length - len(packet_in.getvalue())))
				packet_in.seek(0)
				packet_in_copy = BytesIO(packet_in.getvalue())
				self.log('packet (length {} {}) data: {}'.format(length, length_data.getvalue(), packet_in.getvalue()))

				packet_out = self.try_convert(length, packet_in)
				if packet_out is None:
					packet_out = packet_in_copy
				else:
					convert_success = True
				packet_out_all = BytesIO()
				VarInt.send(len(packet_out.getvalue()), packet_out_all)
				packet_out_all.write(packet_out.getvalue())
				self.target_sock.sendall(packet_out_all.getvalue())
				self.log('sending', packet_out_all.getvalue())

			if self.closed:
				return
			else:
				self.log('Convert success, switching to directly forward mode')
				forward(self.conn, self.target_sock)
		except Exception as e:
			self.log('Connection closed:', e)
		finally:
			self.conn.close()
			self.target_sock.close()

	def try_convert(self, length, packet_in):
		try:
			read_data = BytesIO()
			packet_id = VarInt.read(packet_in, read_data)
			self.log('packet_id =', packet_id)
			if packet_id == HAND_SHAKE_PACKET_ID:
				protocol = VarInt.read(packet_in, read_data)
				address = String.read(packet_in, read_data)
				port = UnsignedShort.read(packet_in, read_data)
				next_state = VarInt.read(packet_in, read_data)
				assert len(read_data.getvalue()) == length
				fake_addr = self.forwarder.config.fake_addr
				pack_out = BytesIO()
				VarInt.send(packet_id, pack_out)
				VarInt.send(protocol, pack_out)
				String.send(fake_addr.address, pack_out)
				UnsignedShort.send(fake_addr.port, pack_out)
				VarInt.send(next_state, pack_out)
				self.log('Converted address {}:{} to {} in HandShakePacket'.format(address, port, fake_addr))
				return pack_out
		except Exception as e:
			self.log('Convert fail:', e)
		return None


class Pipe(threading.Thread):
	def __init__(self, connection, source_sock, target_sock):
		super().__init__()
		self.setDaemon(True)
		self.connection = connection
		self.source_sock = source_sock  # type: socket
		self.target_sock = target_sock  # type: socket

	def run(self):
		try:
			forward(self.source_sock, self.target_sock)
		except Exception as e:
			self.connection.log('Connection closed:', e)
		finally:
			self.source_sock.close()
			self.target_sock.close()
			self.connection.closed = True


class UnsignedShort:
	@staticmethod
	def read(file_object, raw):
		byte = file_object.read(2)
		raw.write(byte)
		return struct.unpack('>H', byte)[0]

	@staticmethod
	def send(value, file_object):
		file_object.write(struct.pack('>H', value))


class VarInt:
	max_bytes = 5

	@classmethod
	def read(cls, file_object, raw):
		number = 0
		# Limit of 'cls.max_bytes' bytes, otherwise its possible to cause
		# a DOS attack by sending VarInts that just keep going
		bytes_encountered = 0
		while True:
			byte = file_object.read(1)
			if len(byte) < 1:
				raise EOFError("Unexpected end of message.")

			raw.write(byte)
			byte = ord(byte)
			number |= (byte & 0x7F) << 7 * bytes_encountered
			if not byte & 0x80:
				break

			bytes_encountered += 1
			if bytes_encountered > cls.max_bytes:
				raise ValueError("Tried to read too long of a VarInt")
		return number

	@staticmethod
	def send(value, file_object):
		out = bytes()
		while True:
			byte = value & 0x7F
			value >>= 7
			out += struct.pack("B", byte | (0x80 if value > 0 else 0))
			if value == 0:
				break
		file_object.write(out)


class String:
	@staticmethod
	def read(file_object, raw):
		length = VarInt.read(file_object, raw)
		s = file_object.read(length)
		raw.write(s)
		return s.decode("utf-8")

	@staticmethod
	def send(value, file_object):
		value = value.encode('utf-8')
		VarInt.send(len(value), file_object)
		file_object.write(value)


def main():
	app = ConnectionForwarder(CONFIG_FILE)
	app.run()


if __name__ == '__main__':
	main()