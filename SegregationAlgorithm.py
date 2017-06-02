L = 'LinuxVM'
W = 'WindowsVM'

class VM(object):
	def __init__(self, vm_id, os_type):
		self.vm_id = vm_id
		self.os_type = os_type

class Host(object):
	def __init__(self, host_id):
		self.host_id = host_id
		self.vms = list()
		self.capacity_total = 10

	def __eq__(self, other):
		return self.host_id == other.host_id

	@property
	def capacity_available(self):
		return (self.capacity_total - len(self.vms))


def count_vms_of_type(os_type, host):
	counter = 0
	for vm in host.vms:
		if vm.os_type == os_type:
			counter += 1
	return counter

def find_pivot(os_type, host_list):
	counter = 0
	for host in host_list:
		amount = count_vms_of_type(os_type, host)
		if amount > counter:
			if host.capacity_available > 0:
				counter = amount
				pivot = host
	return pivot

def find_emptiest(host_list):
	emptiest = host_list[0]
	for host in host_list:
		if host.capacity_available > emptiest.capacity_available:
			emptiest = host
	return emptiest

def has_capacity(vm, host):
	if host.capacity_available > 0:
		return True
	return False

def prepare_pivot(pivot, host_list):
	for vm in pivot.vms:
		if vm.os_type == 'LinuxVM':
			dst_host = find_emptiest(host_list)
			if has_capacity(vm, dst_host):
				migrate_vm(vm=vm, src_host=pivot, dst_host=dst_host)
			else:
				print "Not enought capacity!"

def find_least_host(os_type, host_list):
	
	big_amount = 1000
	least_host = None

	for host in host_list:
		amount_of_windows_vms = count_vms_of_type(os_type, host)
		if amount_of_windows_vms < big_amount and amount_of_windows_vms > 0:
			least_host = host
			big_amount = amount_of_windows_vms
	return least_host

def migrate_vm(vm=None, src_host=None, dst_host=None, os_type=None):
	if src_host == dst_host:
		return
	if vm:
		print "P>>> Migrated %s from %s to %s" % (vm.vm_id, src_host.host_id, dst_host.host_id)
		idx = src_host.vms.index(vm)
		tmp = src_host.vms.pop(idx)
		dst_host.vms.append(tmp)
	else:
		for vm in src_host.vms:
			if vm.os_type == os_type:
				idx = src_host.vms.index(vm)
				tmp = src_host.vms.pop(idx)
				dst_host.vms.append(tmp)
				print "M>>> Migrated %s from %s to %s" % (vm.vm_id, src_host.host_id, dst_host.host_id)
				return


host0 = Host('host0')
host1 = Host('host1')
host2 = Host('host2')
host3 = Host('host3')
host4 = Host('host4')
host5 = Host('host5')

host0.vms.append(VM('vm-1', L))
host0.vms.append(VM('vm-2', W))
host0.vms.append(VM('vm-3', W))
host0.vms.append(VM('vm-4', W))

host1.vms.append(VM('vm-5', L))
host1.vms.append(VM('vm-6', W))
host1.vms.append(VM('vm-7', L))

host2.vms.append(VM('vm-8', L))
host2.vms.append(VM('vm-9', W))
host2.vms.append(VM('vm-10', L))
host2.vms.append(VM('vm-11', W))
host2.vms.append(VM('vm-12', L))

host3.vms.append(VM('vm-13', W))
host3.vms.append(VM('vm-14', L))

host4.vms.append(VM('vm-16', L))
host4.vms.append(VM('vm-17', L))

host5.vms.append(VM('vm-18', W))
host5.vms.append(VM('vm-19', W))
host5.vms.append(VM('vm-20', W))
host5.vms.append(VM('vm-21', L))
host5.vms.append(VM('vm-22', W))
host5.vms.append(VM('vm-23', L))


host_list = [host0, host1, host2, host3, host4, host5]


for i in range(100):
	pivot = find_pivot(W, host_list)
	prepare_pivot(pivot, host_list)
	least_host = find_least_host(W, host_list)
	migrate_vm(src_host=least_host, dst_host=pivot, os_type=W)

print "\n\nThe last pivot: %s\n" % pivot.host_id

for host in host_list:
	for vm in host.vms:
		print host.host_id, vm.vm_id, vm.os_type
	print
