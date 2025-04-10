import nmap, socket
import time
from ipam.models import Prefix, IPAddress
from extras.models import Tag
from extras.scripts import Script, BooleanVar, StringVar, ObjectVar

nmap_arguments = '-sP -PE -PP -PU135,137,161 -PS22,80,135,139,443,515,3389,9100 -PA80,113,443 -T4 --send-ip --release-memory'
#nmap_arguments = '-sn -PE -PP -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -T4 --source-port 53'        # рекомендовано nmap-docs
#nmap_arguments = '-sn --send-ip -PR -PP -T2 --source-port 53'                  # длинные таймауты - находит почти всё (долго)

class IpScan(Script):
    # optional variables in UI here!
    TagBasedScanning = BooleanVar(
        label="Tag Based Scanning?",
        default=True,
        description="Enable Tag Based Scanning to scan only Prefixes with specified Tag.",
    )
    select_tag = ObjectVar(
        model=Tag,
        query_params={},
        label="Scan Tag",
        required=False,
        default=1,
        description="Specify the Tag to filter Subnets to be scanned",
    )

    class Meta:
        name = "IP Scanner"
        description = "Сканирует префиксы (с выбранной меткой или активные) и обновляет IPv4 адреса"
        commit_default = True
        job_timeout = 600

    def run(self, data, commit):
#        self.log_debug(f"Chosen '{data['select_tag']}' tag")
        if data['TagBasedScanning'] and not data['select_tag']:
            return "Selected 'Tag Based Scanning', but tag is not chosen."
        nm = nmap.PortScanner()

        for subnet in Prefix.objects.all():		# extracts all prefixes, in format x.x.x.x/yy:
            s_tags = sorted([tag.name for tag in subnet.tags.all()])
            self.log_info(f'Checking {str(subnet)}: Status is {subnet.status}; Tags is {s_tags}')

            if data['TagBasedScanning'] and str(data['select_tag']) not in s_tags:	# Only scan subnets with the Tag
#                self.log_debug(f"Scan of {subnet.prefix} NOT done (missing '{data['select_tag']}' tag)")
                continue
            if str(subnet.status).lower() != 'active':		# Do not scan not working subnets
#                self.log_debug(f'Scan of {subnet.prefix} NOT done (is not Active)')
                continue
# сканируем подсеть
            nm.scan(hosts=str(subnet), arguments=nmap_arguments)
            self.log_debug(f'{nm.scanstats()}')
# обрабатываем найденные активные адреса
            for host in nm.all_hosts():
#                self.log_debug(f'Find {host} : {nm[host].hostname()}')
                self.update_ip(commit, f'{host}/{subnet.mask_length}', nm[host].hostname())
# обновляем существующие адреса
            for host in subnet.get_child_ips():
                DNS_record = self.host_lookup(host.address)
#                self.log_debug(f'Process {host} : {DNS_record}')
                self.update_ip(commit, str(host.address), DNS_record)
# пауза между сканированиями подсетей
            time.sleep(5)

# поиск имени для адреса
    def host_lookup(self, addr):
        a_str = str(addr).split('/')[0]
        try:
            res =  socket.gethostbyaddr(a_str)
            a_name = res[0]
        except:
            a_name = ''
#        self.log_debug(f'Lookup {a_str}: {a_name}')
        return a_name

# ввод/обновление данных по адресу
    def update_ip(self, commit, ipn, name):
#        self.log_debug(f'Processing {ipn} = {name}')
        try:
            ip_address = IPAddress.objects.get(address=ipn)
#            self.log_debug(f'IP: {ip_address.address}, Name: {ip_address.dns_name}, Desc: {ip_address.description}')
            if name and name.lower() != ip_address.dns_name:
                self.log_success(f'Update {ipn}: {ip_address.dns_name} to {name}')
                if commit:
                    if ip_address.pk and hasattr(ip_address, 'snapshot'):
                        ip_address.snapshot()
                    ip_address.dns_name=name
                    ip_address.full_clean()
                    ip_address.save()
        except IPAddress.DoesNotExist:
            self.log_success(f'Adding new {ipn} = {name}')
            if commit:
                new_address = IPAddress(
                    address = ipn,
                    dns_name = name,
                    description = f'Автоматически добавлено скриптом {self.Meta.name}',
                    )
                new_address.full_clean()
                new_address.save()
