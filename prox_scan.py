# минимальная версия Netbox 4.2
#
# v4.2 - добавлена поддержка объектов MACAddress
# v4.1 - использовано поле VirtualMachine.serial для номера Proxmox VMid

import re
import requests		# для proxmoxer и определения 'username' в http-запросе
import socket		# для проверки соединения по IP
from proxmoxer import ProxmoxAPI

from django.contrib.contenttypes.models import ContentType

from netbox.choices import ColorChoices
from extras.scripts import Script, ObjectVar, FileVar
from users.models import User
from extras.models import Tag
from virtualization.models import ClusterType, Cluster, VirtualMachine, VMInterface
from virtualization.choices import VirtualMachineStatusChoices
from dcim.choices import DeviceStatusChoices, InterfaceTypeChoices
from dcim.models import Interface,MACAddress,Device,DeviceRole,DeviceType,Manufacturer,Site
from ipam.models import Prefix, IPAddress

# должен быть установлен плагин 'netbox_secrets'
try:
    from netbox_secrets.models import SecretRole,Secret,UserKey
    PROX_SECRET_ROLE = 'proxmox_token'	# роль секретов для доступа к Proxmox
except ImportError:
    PROX_SECRET_ROLE = ''		# без доступа к Proxmox API

# цвет для создаваемых объектов
PROX_TAG_COLOR = ColorChoices.COLOR_INDIGO
PROX_COLOR_PVE = ColorChoices.COLOR_DARK_PURPLE
PROX_COLOR_PBS = ColorChoices.COLOR_PURPLE

# значения для автоматически добавляемых скриптом объектов
DESC_STR = 'Создано скриптом '
TAG_AUTO = 'prox_scan'		# метка
CLUSTER_TYPE = 'Proxmox'	# тип кластеров
DEVICE_TYPE = 'ProxScan'	# тип устройств
DEVICE_HEIGHT = 2.0		# высота устройств по умолчанию
DEVICE_ROLE_PVE = 'PVE'		# роль устройств P.Virtual Environment
DEVICE_ROLE_PBS = 'PBS'		# роль устройств P.Backup Server
MANUFACTURER = 'ProxScan'	# условный изготовитель
VM_DEFAULT_ROLE = 'server'	# роль по умолчанию для вирт.машин

# тип для физических интерфейсов
IFACE_DEFAULT_TYPE = InterfaceTypeChoices.TYPE_1GE_TX_FIXED
# TYPE_10GE_SFP_PLUS
# типы для виртуальных интерфейсов
IFACE_VIRTUAL_TYPE = InterfaceTypeChoices.TYPE_VIRTUAL
IFACE_BRIDGE_TYPE = InterfaceTypeChoices.TYPE_BRIDGE
#IFACE_LAG_TYPE = InterfaceTypeChoices.TYPE_LAG

PVE_DEFAULT_PORT = 8006
PBS_DEFAULT_PORT = 8007
PROX_DEFAULT_USER = 'root@pam'	# обязательный параметр, но не используется


class ProxmoxImport(Script):

    class Meta:
        name = "Proxmox import"
        description = "Просматривает IP адреса, ищет Proxmox и обновляет списки 'Devices', 'Interfaces', 'Clusters' и 'Virtual Machines'"
        commit_default = True
        job_timeout = 90

    select_site = ObjectVar(
        model=Site,
        query_params={},
        label="Сайт:",
        default=1,		# id сайта по умолчанию
        required=True,
        description="Выберите место для размещения новых устройств (хостов)",
    )

    key_file = FileVar(
        required=False,
        description="Загрузите файл приватного ключа для доступа к API Proxmox",
    )


# проверка доступности порта
    def is_port_open(self, host, port):
        s = socket.socket()
        s.settimeout(0.2)			# таймаут для чуть большей скорости
        result = s.connect_ex((host, port))	# попытка присоединения через порт
        s.close()
        return result == 0

# установка соединения с хостом Proxmox с использованием токена
    def connect(self, server_addr, host_dev, masterkey, secret_role):
        if not masterkey:		# нет доступа к API
            return None
        ip4 = str(server_addr).split('/')[0]
        if self.is_port_open(ip4, PVE_DEFAULT_PORT):
            dev_port = PVE_DEFAULT_PORT
            prox_service = DEVICE_ROLE_PVE
        elif self.is_port_open(ip4, PBS_DEFAULT_PORT):
            dev_port = PBS_DEFAULT_PORT
            prox_service = DEVICE_ROLE_PBS
        else:
            return None		# прочие сервисы игнорируем
#        self.log_debug(f"Обнаружен {prox_service} по адресу: {ip4}", host_dev)
# секрет с нужной ролью у девайса должен быть только один
        try:
            prox_secret = Secret.objects.get(role=secret_role, assigned_object_id=host_dev.id)
        except:
            self.log_warning(f"Не задан токен устройства '{host_dev.name}'", host_dev)
            return None		# нет девайса/нет токена для работы
        try:
            prox_secret.decrypt(masterkey)
        except:
            self.log_failure(f"Загружен не соответствующий файл ключа!")
            return None
# соединение с API
#        self.log_debug(f"Check {prox_service} API at: {host_dev.name}={ip4}:{dev_port} with token {prox_secret.name}={prox_secret.plaintext}", host_dev)
        api = ProxmoxAPI(ip4, port=dev_port, user=PROX_DEFAULT_USER, service=prox_service,
                         token_name=prox_secret.name, token_value=prox_secret.plaintext, verify_ssl=False)
        # проверка доступности API
        if api:
            try:
#                realms = api.access.domains.get()		# работает без аутентификации
#                self.log_debug(f"Proxmox realms: {realms}")
                vers = api.version.get()
#                self.log_debug(f"Версия Proxmox: {vers}", host_dev)
            except:
                self.log_failure(f"Анализ '{host_dev.name}' невозможен: невалидный токен {prox_secret.name} !", host_dev)
                return None
        else:
            self.log_failure(f"Соединение с {prox_service} at: {ip4}:{dev_port} не установлено!")
        return api

# поиск/создание объекта Tag нужного вида
    def get_tag_auto(self, commit, name=TAG_AUTO):
        try:
            a_tag = Tag.objects.get(name=name)	# поиск тега
        except:
            if commit:
                self.log_success(f"Нет тега '{name}', создаем.")
                a_tag = Tag(
                    name = name,
                    slug = name.lower(),
                    color = PROX_TAG_COLOR,
                    description = f"Метка для объектов, созданных скриптом '{self.Meta.name}'",
                    )
                a_tag.full_clean()
                a_tag.save()
            else:
                return None
#        self.log_debug(f"Tag ID: {a_tag.id}", a_tag)
        return a_tag

    def get_cluster_type(self, commit, name=CLUSTER_TYPE, set_tag=None):
        try:
            c_type = ClusterType.objects.get(name=name)	# проверка наличия типа кластера
        except:
            if commit:
                self.log_success(f"Нет типа кластера '{name}', создаем.")
                c_type = ClusterType(
                    name = name,
                    slug = name.lower(),
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                c_type.full_clean()
                c_type.save()
                if set_tag:
                    c_type.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Cluster type ID: {c_type.id}, '{c_type.name}'", c_type)
        return c_type

    def get_cluster(self, commit, name, c_type, set_tag=None, description=None):
        try:
            c_clust = Cluster.objects.get(name=name)	# проверка наличия кластера
        except:
            if commit:
                self.log_success(f"Нет кластера '{name}', создаем.")
                c_clust = Cluster(
                    name = name,
                    type = c_type,
                    description = description,
                    comments = f"{DESC_STR}'{self.Meta.name}'",
                    )
                c_clust.full_clean()
                c_clust.save()
                if set_tag:
                    c_clust.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Cluster ID: {c_clust.id}, '{c_clust.name}'", c_clust)
        return c_clust

    def get_manufacturer(self, commit, name=MANUFACTURER, set_tag=None):
        try:
            p_man = Manufacturer.objects.get(name=name)	# проверка наличия производителя
        except:
            if commit:
                self.log_success(f"Нет производителя '{name}', создаем.")
                p_man = Manufacturer(
                    name = name,
                    slug = name.lower(),
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                p_man.full_clean()
                p_man.save()
                if set_tag:
                    p_man.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Manufacturer ID: {p_man.id}, '{p_man.name}'", p_man)
        return p_man

    def get_device_type(self, commit, name=DEVICE_TYPE, units=DEVICE_HEIGHT, set_manufacturer=None, set_tag=None):
        try:
            d_type = DeviceType.objects.get(model=name)	# проверка наличия типа устройств
        except:
            if commit:
                self.log_success(f"Нет типа устройств '{name}', создаем.")
                d_type = DeviceType(
                    manufacturer = set_manufacturer,	# нужно проверять!
                    model = name,
                    slug = name.lower(),
                    u_height = units,
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                d_type.full_clean()
                d_type.save()
                if set_tag:
                    d_type.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Device type ID: {d_type.id}, '{d_type.name}'", d_type)
        return d_type

    def get_secret_role(self, commit, name, set_tag=None):
        if not name:
            return None
        try:
            s_role = SecretRole.objects.get(name=name)	# проверка наличия роли секретов
        except:
            if commit:
                self.log_success(f"Нет роли секретов '{name}', создаем.")
                s_role = SecretRole(
                    name = name,
                    slug = name.lower(),
                    description = "Токен доступа к Proxmox API",
                    comments = f"{DESC_STR}'{self.Meta.name}'",
                    )
                s_role.full_clean()
                s_role.save()
                if set_tag:
                    s_role.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Secret role ID: {s_role.id}, '{s_role.name}'", s_role)
        return s_role

    def get_device_role(self, commit, name=DEVICE_ROLE_PVE, set_tag=None):
        try:
            d_role = DeviceRole.objects.get(name=name)	# проверка наличия роли устройств
        except:
            if commit:
                self.log_success(f"Нет роли устройств '{name}', создаем.")
                d_role = DeviceRole(
                    name = name,
                    color = PROX_COLOR_PVE if name==DEVICE_ROLE_PVE else PROX_COLOR_PBS,
                    slug = name.lower(),
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                d_role.full_clean()
                d_role.save()
                if set_tag:
                    d_role.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Device role ID: {d_role.id}, '{d_role.name}'", d_role)
        return d_role

    def get_device(self, commit, name, site, d_role=None, d_type=None, v_cluster=None, \
                        ipaddr=None, status=DeviceStatusChoices.STATUS_ACTIVE, set_tag=None):
#        self.log_debug(f"Find device '{name}': site={site.id} role={str(d_role)} type={str(d_type)} cluster={str(v_cluster)} addr={str(ipaddr)}")
        try:
            c_node = Device.objects.get(name=name)	# проверка наличия устройства
        except:
            if commit and name:		# создавать безымянные не будем
                self.log_success(f"Нет устройства '{name}', создаем.")
                c_node = Device(
                    name = name,
                    site = site,
                    role = d_role,
                    device_type = d_type,
                    cluster = v_cluster,		# кластер виртуализации
                    status = status,
                    comments = f"{DESC_STR}'{self.Meta.name}'",
                    )
                c_node.full_clean()
                if ipaddr:
                    c_node.primary_ip4 = ipaddr
                c_node.save()
                if set_tag:
                    c_node.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
#        self.log_debug(f"Device ID: {c_node.id}, '{c_node.name}'", c_node)
        return c_node

    def update_device(self, commit, dev, d_role=None, v_cluster=None, status=None, ip4=None, description=None):
        upd = False
        upd = upd or (d_role and d_role != dev.role)
        upd = upd or (v_cluster and v_cluster != dev.cluster)
        upd = upd or (status and status != dev.status)
        upd = upd or (ip4 and ip4 != dev.primary_ip4)
        upd = upd or (description and description != dev.description)
        if (not commit) or (not upd):
            return False
        u_str = []
        if dev.pk and hasattr(dev, 'snapshot'):
            dev.snapshot()		# запись для истории изменений
        if d_role and d_role != dev.role:
            u_str.append(f"role={str(d_role)}")
            dev.role = d_role
        if v_cluster and v_cluster != dev.cluster:
            u_str.append(f"cluster={v_cluster.name}")
            dev.cluster = v_cluster
        if status and status != dev.status:
            u_str.append(f"status={status}")
            dev.status = status
        if description and description != dev.description:
            u_str.append(f"{description}")
            dev.description = description
        if ip4 and ip4 != dev.primary_ip4:
            u_str.append(f"ip4={str(ip4)}")
            dev.primary_ip4 = ip4
        self.log_success(f"Обновляем устройство '{dev.name}': {', '.join(u_str)}", dev)
        try:
            dev.full_clean()
        except:
            self.log_warning(f"Какое-то несоответствие при обновлении устройства '{dev.name}' !", dev)
        dev.save()
        return True

    def get_iface(self, commit, dev, name, iface_type=IFACE_DEFAULT_TYPE, mtu=None, iface_enabled=True, bridge_iface=None, set_tag=None):
        try:
            n_iface = Interface.objects.get(device=dev, name=name)	# проверка наличия интерфейса
        except:
            if commit:
                self.log_success(f"Нет интерфейса '{name}', создаем.")
                n_iface = Interface(
                    device = dev,
                    name = name,
                    type = iface_type,
                    mtu = mtu,
                    enabled = iface_enabled,
                    bridge = bridge_iface,
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                n_iface.full_clean()
                n_iface.save()
                if set_tag:
                    n_iface.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
        else:
            self.update_dev_iface(commit, n_iface, mtu, iface_enabled, bridge_iface)
#        self.log_debug(f"Interface ID: {n_iface.id}, '{n_iface.name}'", n_iface)
        return n_iface

    def update_dev_iface(self, commit, iface, iface_mtu, iface_enabled, iface_bridge):
        upd = False
# обновляем MTU только если есть значение, вручную установленное - не очищаем
        upd = upd or iface_mtu and (str(iface_mtu) != str(iface.mtu))
        upd = upd or (bool(iface_enabled) != iface.enabled)
        upd = upd or (iface_bridge != iface.bridge)
        if (not commit) or (not upd):
            return False
        u_str =[]
        if iface.pk and hasattr(iface, 'snapshot'):
            iface.snapshot()		# запись для истории изменений
        if iface_mtu and (str(iface_mtu) != str(iface.mtu)):
            u_str.append(f"MTU={iface_mtu}")
            iface.mtu = iface_mtu
        if bool(iface_enabled) != iface.enabled:
            u_str.append(f"enabled={iface_enabled}")
            iface.enabled = bool(iface_enabled)
        if iface_bridge != iface.bridge:
            u_str.append(f"bridge={iface_bridge}")
            iface.bridge = iface_bridge
        self.log_success(f"Обновляем интерфейс '{iface.name}': {', '.join(u_str)}", iface)
        iface.full_clean()
        iface.save()
        return True

# поиск/создание IP-адреса
    def get_ip4(self, commit, ipn):
#        self.log_debug(f"Поиск адреса {ipn}")
        try:
            ip_address = IPAddress.objects.get(address=ipn)
#            self.log_debug(f"IP: {ip_address.address}, Name: {ip_address.dns_name}", ip_address)
            return ip_address
        except IPAddress.DoesNotExist:
            if commit:
                self.log_success(f"Нет адреса '{ipn}', создаем.")
                ip_address = IPAddress(
                    address = ipn,
                    description = f"{DESC_STR}'{self.Meta.name}'",
                    )
                ip_address.full_clean()
                ip_address.save()
                return ip_address
        return None

    def update_ip4(self, commit, iface, ip4):
        ip_address = self.get_ip4(commit, ip4)
        if not ip_address:
            self.log_warning(f"Адрес привязки {ip4} для интерфейса '{iface.name}' не найден!", iface)
            return False
        real = hasattr(iface, 'mark_connected')	# 'true' только для физических интерфейсов
        if real:
            interface_ct = ContentType.objects.get_for_model(Interface).pk
        else:
            interface_ct = ContentType.objects.get_for_model(VMInterface).pk
        upd = (ip_address.assigned_object_type_id != interface_ct) or (ip_address.assigned_object_id != iface.id)
        if (not commit) or (not upd):
            return False
        self.log_success(f"Связка адреса {ip4} -> interface {iface.id} '{iface.name}' dev.real={real}", iface)
        if ip_address.pk and hasattr(ip_address, 'snapshot'):
            ip_address.snapshot()		# запись для истории изменений
        ip_address.assigned_object_type_id = interface_ct
        ip_address.assigned_object_id = iface.id
        ip_address.full_clean()
        ip_address.save()
        return True

# поиск/создание/обновление виртуальной машины
    def get_vm(self, commit, name, status, v_cluster, v_role=None, serial=None, cpus=0, mem=0, disk=0,
                    set_tag=None, description=None):
        try:
            vm = VirtualMachine.objects.get(cluster=v_cluster, name=name)	# проверка наличия ВМ в кластере
        except:
            if commit:
                self.log_success(f"Нет вирт.машины '{name}', создаем.")
                vm = VirtualMachine(
                    name = name,
                    status = status,
                    cluster = v_cluster,	# кластер виртуализации
                    role = v_role if v_role else self.get_device_role(commit, name=VM_DEFAULT_ROLE, set_tag=set_tag),
                    serial = serial,
                    vcpus = cpus,
                    memory = mem,		# (MB)
                    disk = disk,		# (MB)
                    description = description,
                    comments = f"{DESC_STR}'{self.Meta.name}'",
                    )
                vm.full_clean()
                vm.save()
                if set_tag:
                    vm.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
        else:
            self.update_vm(commit, vm, status, v_cluster, serial, cpus, mem, disk, description)
#        self.log_debug(f"VM ID: {vm.id}, '{vm.id}'", vm)
        return vm

    def update_vm(self, commit, dev, status, v_cluster, vm_serial, cpus, mem, disk, description):
#        self.log_debug(f"ВМ {dev.id}: {dev.status}, cluster={dev.cluster}, ser={dev.serial}, cpu={dev.vcpus}, mem={dev.memory}, disk={dev.disk}, {dev.description}")
        serial = str(vm_serial)
        upd = False
        upd = upd or (status and status != dev.status)
        upd = upd or (v_cluster and v_cluster != dev.cluster)
        upd = upd or (serial and serial != str(dev.serial))
        upd = upd or (cpus and int(cpus) != int(dev.vcpus))		# в Proxmox сокеты в целых числах
        upd = upd or (mem and mem != dev.memory)
        upd = upd or (disk and disk != dev.disk)
        upd = upd or (description and description != dev.description)
        if (not commit) or (not upd):
            return False
        u_str = []
        if dev.pk and hasattr(dev, 'snapshot'):
            dev.snapshot()		# запись для истории изменений
        if status and status != dev.status:
            u_str.append(f"status={status}")
            dev.status = status
        if v_cluster and v_cluster != dev.cluster:
            u_str.append(f"cluster={v_cluster}")
            dev.cluster = v_cluster
        if serial and (serial != str(dev.serial)):
            u_str.append(f"serial={serial}")
            dev.serial = serial
        if cpus and (int(cpus) != int(dev.vcpus)):
            u_str.append(f"cpu={cpus}")
            dev.vcpus = cpus
        if mem and mem != dev.memory:
            u_str.append(f"mem={mem}")
            dev.memory = mem
        if disk and disk != dev.disk:
            u_str.append(f"disk={disk}")
            dev.disk = disk
        if description and description != dev.description:
            u_str.append(f"{description}")
            dev.description = description
        self.log_success(f"Обновляем ВМ {dev.name}: {', '.join(u_str)}", dev)
        dev.full_clean()
        dev.save()
        return True

# обновление primary_ip4, если у ВМ только один адрес из всех интерфейсов
# если ничего не нашлось или адресов много - ничего не делать
    def update_vm_ip(self, commit, vdev):
#        self.log_debug(f"VM id: {vdev.id}, '{vdev.name}'", vdev)
        ifaces = VMInterface.objects.filter(virtual_machine=vdev.id)	# список интерфейсов ВМ
        vm_ip_list = []
        for iface in ifaces:
            for ip in IPAddress.objects.filter(assigned_object_type_id=ContentType.objects.get_for_model(VMInterface).pk,
                                            assigned_object_id=iface.id):	# собираем адреса интерфейса
#                self.log_debug(f"VM id: {vdev.id}, IFace id: {iface.id}, IP: {ip}", ip)
                vm_ip_list.append(str(ip))
#        self.log_debug(f"VM id: {vdev.id}, IP: {vm_ip_list}", vdev)
        if len(vm_ip_list)==1:
            ip_prim = IPAddress.objects.get(address=vm_ip_list[0])
            if commit and (vdev.primary_ip4 != ip_prim):
                self.log_success(f"Обновляем primary адрес VM '{vdev.name}' -> {ip_prim}", vdev)
                if vdev.pk and hasattr(vdev, 'snapshot'):
                    vdev.snapshot()		# запись для истории изменений
                vdev.primary_ip4 = ip_prim
                vdev.save()
            return vdev.primary_ip4
        elif commit and len(vm_ip_list) > 1 and not vdev.primary_ip4:
            self.log_warning(f"У ВМ '{vdev.name}' несколько IP-адресов, Primary адрес надо выбрать вручную.", vdev)
        return None

# разбор строки описания носителя. Пример: 'sas_vm:vm-152-disk-0,size=120G'
    def parse_disk_conf(self, conf_str: str):
        if 'media=cdrom' in conf_str:
            return 0		# не считаем
        size, unit = re.search(r'size=(\d+)([GTM])', conf_str).groups()
        if unit == 'G':
            size = int(size) * 1000
        elif unit == 'T':
            size = int(size) * 1000 * 1000
        else:
            size = int(size)	# Netbox считает диски в МБ
#        self.log_debug(f"Disk size parsed: {conf_str} -> {size}")
        return size

# подсчет размера дисков виртуальной машины по конфигурации
    def calc_disks(self, vm_config):
        disk_size = 0
        if 'rootfs' in vm_config:
            disk_size += self.parse_disk_conf(vm_config['rootfs'])
# дополнительно считаем разные типы дисков (scsi, mp, sata, ide)
        device_id = 0
        while f'scsi{device_id}' in vm_config:
            disk_size += self.parse_disk_conf(vm_config[f'scsi{device_id}'])
            device_id += 1
        device_id = 0
        while f'mp{device_id}' in vm_config:
            disk_size += self.parse_disk_conf(vm_config[f'mp{device_id}'])
            device_id += 1
        device_id = 0
        while f'sata{device_id}' in vm_config:
            disk_size += self.parse_disk_conf(vm_config[f'sata{device_id}'])
            device_id += 1
        device_id = 0
        while f'ide{device_id}' in vm_config:
            disk_size += self.parse_disk_conf(vm_config[f'ide{device_id}'])
            device_id += 1
        return disk_size

# создаем интерфейс вирт.машины
    def make_vm_iface(self, commit, vm, net_dev:str, net_str:str, net_info=None, set_tag=None):
#        self.log_debug(f"VMInterface string: {net_str}", vm)
        net_config = dict(map(lambda x: tuple(x.split('=')), net_str.split(',')))
# Proxmox модели сетевух: e1000 | e1000-82540em | e1000-82544gc | e1000-82545em | e1000e | i82551 | i82557b | i82559er | ne2k_isa | ne2k_pci | pcnet | rtl8139 | virtio | vmxnet3
        iface_mac = None
        for attribute in ('hwaddr', 'virtio', 'e1000', 'e1000e', 'rtl8139', 'vmxnet3'):
            if attribute in net_config:
                iface_mac = net_config[attribute]
                break
        iface_name = net_config['name'] if 'name' in net_config else \
                    self.parse_agent_netinfo(net_info, iface_mac, 'name') or net_dev
        iface_mtu = net_config['mtu'] if 'mtu' in net_config else None
        iface_enabled = (not net_config['link_down']) if 'link_down' in net_config else True
# в Netbox атрибуты интерфейса parent и bridge должны быть в той же вирт.машине - не используем, пишем в description
        iface_bridge = net_config['bridge'] if 'bridge' in net_config else ''
# список IPv4 для привязки к интерфейсу
        ip4 = [net_config['ip']] if 'ip' in net_config else self.parse_agent_netinfo(net_info, iface_mac, 'ip')
#        self.log_debug(f"VMInterface: {iface_name}: {iface_mac}, {iface_mtu}, {iface_enabled}, {iface_bridge}, {ip4}")
        try:
            n_iface = VMInterface.objects.get(virtual_machine=vm, name=iface_name)	# проверка наличия интерфейса
        except:
            if commit:
                self.log_success(f"Нет интерфейса ВМ '{iface_name}', создаем.")
                n_iface = VMInterface(
                    virtual_machine = vm,
                    name = iface_name,
                    mtu = iface_mtu,
                    enabled = iface_enabled,
                    description = self.make_vm_iface_description(iface_bridge),
                    )
                n_iface.full_clean()
                n_iface.save()
                if set_tag:
                    n_iface.tags.add(set_tag)		# теги после создания объекта
            else:
                return None
        else:
            self.update_vm_iface(commit, n_iface, iface_name, iface_mtu, iface_enabled, iface_bridge)
#        self.log_debug(f"VMInterface ID: {n_iface.id}, '{n_iface.name}'", n_iface)
        if iface_mac:
#            self.log_debug(f"Link VM iface '{n_iface.name}' -> MAC={iface_mac}", n_iface)
            self.update_mac(commit, n_iface, iface_mac, set_tag)
        if ip4:
#            self.log_debug(f"Link VM iface '{n_iface.name}' -> IP={ip4}", n_iface)
            for ip in ip4:
                self.update_ip4(commit, n_iface, ip)	# привязываем адрес(а) к интерфейсу
        return n_iface

    def make_vm_iface_description(self, bridge: str):
        v_bridge = f"Host bridge={bridge}" if bridge else ''
#        return f"{v_bridge}{DESC_STR}'{self.Meta.name}'"
        return v_bridge

# поиск нужного атрибута в описании сети от qemu-агента
    def parse_agent_netinfo(self, net_info, mac, attr):
        if not (net_info and mac):
            return None
        for vm_interface in net_info['result']:
            if vm_interface['hardware-address'].lower() != mac.lower():	# ищем заданный MAC-address
                continue
            if attr=='name':
                return vm_interface['name']
            elif attr=='ip':
                iface_ip_list = []
                for ip in vm_interface['ip-addresses']:		# собираем IP-адреса интерфейса
                    if ip['ip-address-type'] == 'ipv4':		# пропускаем IPv6
                        iface_ip_list.append(f"{ip['ip-address']}/{ip['prefix']}")
# возвращаем список
                return iface_ip_list
        return None

    def update_vm_iface(self, commit, iface, iface_name, iface_mtu, iface_enabled, iface_bridge):
        upd = False
        upd = upd or (iface_name and iface_name != iface.name)
        upd = upd or (iface_mtu and int(iface_mtu) != iface.mtu) or (not iface_mtu and iface.mtu)
        upd = upd or (bool(iface_enabled) != iface.enabled)
        upd = upd or (iface.description != self.make_vm_iface_description(iface_bridge))
        if (not commit) or (not upd):
            return False
        self.log_success(f"Обновляем интерфейс ВМ {iface.name}: {iface_name}, mtu={iface_mtu}, enabled={iface_enabled}, bridge={iface_bridge}", iface)
        if iface.pk and hasattr(iface, 'snapshot'):
            iface.snapshot()		# запись для истории изменений
        if iface_name:
            iface.name = iface_name
        if iface_mtu:
            iface.mtu = int(iface_mtu)
        else:
            iface.mtu = None
        iface.enabled = bool(iface_enabled)
        iface.description = self.make_vm_iface_description(iface_bridge)
        iface.full_clean()
        iface.save()
        return True

# создание MAC-адреса
    def make_MAC(self, macaddr, set_tag=None):
        self.log_success(f"Нет MAC-адреса '{macaddr}', создаем.")
        mac = MACAddress(
            mac_address = macaddr,
            description = f"{DESC_STR}'{self.Meta.name}'",
            )
        mac.full_clean()
        mac.save()
        if set_tag:
            mac.tags.add(set_tag)		# теги после создания объекта
#        self.log_debug(f"MAC: {mac.mac_address}, pk: {mac.pk}", mac)
        return mac

# поиск MAC-адреса для определенного интерфейса
    def get_MAC(self, commit, iface, macaddr, set_tag=None):
#        self.log_debug(f"Поиск MAC-адреса {macaddr} для интерфейса id={iface.id} '{iface.name}'", iface)
        mac_list = MACAddress.objects.filter(mac_address=macaddr)	# выбираем все сразу
        if len(mac_list)==0:
            if commit:
                return self.make_MAC(macaddr, set_tag)
        else:
            for mac in mac_list:
                if mac.assigned_object_id == iface.id:	# нашли уже привязанный
                    return mac
            for mac in mac_list:
                if not mac.assigned_object:		# нашли свободный
                    return mac
            if commit:
                return self.make_MAC(macaddr, set_tag)	# все заняты - делаем новый
        return None

# привязка MAC-адреса к интерфейсу виртуальной машины
    def update_mac(self, commit, iface, iface_mac, set_tag):
        mac_address = self.get_MAC(commit, iface, iface_mac, set_tag)
        if not mac_address:
            self.log_warning(f"MAC-адрес {iface_mac} для интерфейса '{iface.name}' не найден!", iface)
            return False
        interface_ct = ContentType.objects.get_for_model(VMInterface).pk
        upd = (mac_address.assigned_object_type_id != interface_ct) or (mac_address.assigned_object_id != iface.id)
        if (not commit):
            return not upd
        if upd:
            self.log_success(f"Связка MAC-адреса {iface_mac} -> interface {iface.id} '{iface.name}'", iface)
            if mac_address.pk and hasattr(mac_address, 'snapshot'):
                mac_address.snapshot()		# запись для истории изменений
            mac_address.assigned_object_type_id = interface_ct
            mac_address.assigned_object_id = iface.id
            mac_address.full_clean()
            mac_address.save()
# делаем MAC первичным в любом случае (у нас только по одному MAC-у на интерфейс)
        if iface.primary_mac_address != mac_address:
            self.log_success(f"Обновляем primary MAC-адрес интерфейса '{iface.name}' -> {mac_address}", iface)
            if iface.pk and hasattr(iface, 'snapshot'):
                iface.snapshot()		# запись для истории изменений
            iface.primary_mac_address = mac_address
            iface.save()
        return True

    def make_dev_ifaces(self, commit, prox, node, node_dev, set_tag):
#        self.log_debug(f"Node {node['node']}: network={prox.nodes(node['node']).network.get()}", node_dev)
        ifaces = sorted(prox.nodes(node['node']).network.get(), key=lambda x: x['type'], reverse=True)	# интерфейсы по типу, сначала ethernet
# перебираем интерфейсы хоста
        for iface in ifaces:
#            self.log_debug(f"IFace {iface['iface']}: {iface}")
            i_status = ('active' in iface) and iface['active']
            i_mtu = iface['mtu'] if 'mtu' in iface else None
            i_bridge = None
            if iface['type'] == 'eth':
                i_type = IFACE_DEFAULT_TYPE
#                self.log_debug(f"Ethernet {iface['iface']}: active={i_status}, mtu={i_mtu}")
            elif iface['type'] == 'bridge':
                i_type = IFACE_BRIDGE_TYPE
                if 'bridge_ports' in iface:		# ищем порт - должен уже существовать для привязки
                    i_bridge = self.get_iface(False, node_dev, iface['bridge_ports'])
#                self.log_debug(f"Bridge {iface['iface']}: bridge_ports={i_bridge}, active={i_status}, mtu={i_mtu}")
            else:
                i_type = IFACE_VIRTUAL_TYPE
                self.log_warning(f"Неизвестный тип интерфейса {iface['iface']}: {iface['type']}")
# делаем/обновляем интерфейс (Proxmox не показывает MAC для интерфейсов хоста - не используем)
            dev_iface = self.get_iface(commit, node_dev, iface['iface'], iface_type=i_type,
                                    mtu=i_mtu, iface_enabled=i_status, bridge_iface=i_bridge, set_tag=set_tag)
            if 'cidr' in iface and dev_iface:
                self.update_ip4(commit, dev_iface, iface['cidr'])
        return True

# проверка и обновление PVE
    def check_pve(self, commit, prox, host_ip, site, set_tag):
        dev_name=host_ip.dns_name.split('.')[0]		# выбираем хост по DNS-адресу
        result = {'name':dev_name, 'nodes':0, 'vms':0}
        try:
            cluster_name=prox.cluster.status.get()[0]['name']
        except:
            self.log_warning(f"Ошибка запроса (недостаточные привилегии токена)!")
            return result
        result['name'] = cluster_name
        cluster_type = self.get_cluster_type(commit, set_tag=set_tag)
#        self.log_info(f"Cluster {cluster_name}  status: {prox.cluster.status.get()}")
#        self.log_info(f"Cluster {cluster_name} options: {prox.cluster.options.get()}")
        cluster = self.get_cluster(commit, cluster_name, cluster_type,
                                    set_tag=set_tag, description=prox.cluster.options.get()['description'])
        if not cluster:		# не удалось создать кластер?
            return result
# по всем нодам кластера
        node_list = prox.nodes().get()
        result['nodes'] = len(node_list)
        vm_count = 0
        for node in node_list:
#            self.log_debug(f"Node {node['node']}: {node}")
            node_status = DeviceStatusChoices.STATUS_OFFLINE if node['status'] != 'online' else DeviceStatusChoices.STATUS_ACTIVE
            if len(node_list)>1:
                node_name = node['node']		# выбираем хост по имени ноды (не проверяем)
            else:
                node_name = dev_name
# ищем устройство (создаем, если их несколько в кластере)
            node_dev = self.get_device(commit, name=node_name, site=site,
                                        d_role=self.get_device_role(commit, name=DEVICE_ROLE_PVE, set_tag=set_tag),
                                        d_type=self.get_device_type(commit, set_tag=set_tag),
                                        v_cluster=cluster, status=node_status, set_tag=set_tag)
            if node['status'] != 'online':		# не работает нода в кластере ?
                continue
#            self.log_debug(f"Node {node['node']}: status={prox.nodes(node['node']).status.get()}", node_dev)
            self.make_dev_ifaces(commit, prox, node, node_dev, set_tag=set_tag)
# теперь обновляем хост (если нода 'online')
            self.update_device(commit, node_dev, ip4=host_ip if node_name==dev_name else None,
                            d_role=self.get_device_role(False, name=DEVICE_ROLE_PVE),
                            v_cluster=cluster, status=node_status,
                            description=f"Proxmox VE {prox.version.get()['version']}, cpu={node['maxcpu']}, mem={int(int(node['maxmem'])/1024**3)} GiB")

# перебираем вирт.контейнеры
            for vm in prox.nodes(node['node']).lxc.get():
                vm_count += 1
#                self.log_debug(f"LXC {vm['name']}: {vm}")
                vm_stat = VirtualMachineStatusChoices.STATUS_ACTIVE if vm['status'] == 'running' else VirtualMachineStatusChoices.STATUS_OFFLINE
                vm_conf = prox.nodes(node['node']).lxc(vm['vmid']).config.get()
#                self.log_debug(f"Conf {vm['name']}: {vm_conf}")
                descr = f"VM тип=LXC, OStype={vm_conf['ostype']}"
# делаем/обновляем ВМ
                nvm = self.get_vm(commit, vm['name'], vm_stat, cluster, serial=vm['vmid'],
                                cpus=vm['cpus'], mem=int(vm_conf['memory']), disk=self.calc_disks(vm_conf),
                                set_tag=set_tag, description=descr)
                if not nvm:		# не удалось создать?
                    continue
# создаем/обновляем интерфейсы ВМ
                net_device_id = 0
                while f'net{net_device_id}' in vm_conf:
                    self.make_vm_iface(commit, nvm, f'net{net_device_id}', vm_conf[f'net{net_device_id}'], set_tag=set_tag)
                    net_device_id += 1
# теперь обновляем IP у ВМ
                self.update_vm_ip(commit, nvm)

# перебираем вирт.машины
            for vm in prox.nodes(node['node']).qemu.get():
                vm_count += 1
                vm_conf = prox.nodes(node['node']).qemu(vm['vmid']).config.get()
#                self.log_debug(f"QEMU {vm['name']}: {vm}")
#                self.log_debug(f"Conf {vm['name']}: {vm_conf}")
#                self.log_debug(f"Stat {vm['name']}: {prox.nodes(node['node']).qemu(vm['vmid']).status.current.get()}")
                if vm['status'] == 'running':
                    vm_stat = VirtualMachineStatusChoices.STATUS_ACTIVE
                    try:
                        vm_netinfo = prox.nodes(node['node']).qemu(vm['vmid']).agent.get('network-get-interfaces') if 'agent' in vm_conf and vm_conf['agent'] else None
                    except:
                        vm_netinfo = None
                else:
                    vm_stat = VirtualMachineStatusChoices.STATUS_OFFLINE
                    vm_netinfo = None
#                self.log_debug(f"Info {vm['name']}: {vm_netinfo}")
                descr = f"VM тип=QEMU, OStype={vm_conf['ostype']}"
# делаем/обновляем ВМ
                nvm = self.get_vm(commit, vm['name'], vm_stat, cluster, serial=vm['vmid'],
                                cpus=vm['cpus'], mem=int(vm_conf['memory']), disk=self.calc_disks(vm_conf),
                                set_tag=set_tag, description=descr)
                if not nvm:		# не удалось создать?
                    continue
# создаем/обновляем интерфейсы ВМ
                net_device_id = 0
                while f'net{net_device_id}' in vm_conf:
                    self.make_vm_iface(commit, nvm, f'net{net_device_id}', vm_conf[f'net{net_device_id}'], net_info=vm_netinfo, set_tag=set_tag)
                    net_device_id += 1
# теперь обновляем IP у ВМ
                self.update_vm_ip(commit, nvm)
        result['vms'] = vm_count
        return result

# проверка и обновление PBS
    def check_pbs(self, commit, prox, node_dev, host_ip, set_tag):
#        self.log_debug(f"PBS ping status: {prox.get('ping')}", node_dev)
        node = {'node':node_dev.name}			# для совместимости в функции make_dev_ifaces
        try:
            node_status = prox.nodes(node['node']).status.get()
        except:
            self.log_warning(f"Ошибка запроса (недостаточные привилегии токена)!")
            return {'name':node_dev.name}
#        self.log_debug(f"Node {node['node']}: {node_status}", node_dev)
        self.make_dev_ifaces(commit, prox, node, node_dev, set_tag=set_tag)
# теперь обновляем хост (статус делаем 'online')
        self.update_device(commit, node_dev, d_role=self.get_device_role(False, name=DEVICE_ROLE_PBS), ip4=host_ip,
                description=f"Proxmox BS {prox.version.get()['version']}, cpu={node_status['cpuinfo']['cpus']}, mem={int(int(node_status['memory']['total'])/1024**3)} GiB")
        return {'name':node_dev.name}

################################################################################
# основной модуль

    def run(self, data, commit):

# подготовка нужных объектов
        def_site = data['select_site']
#        self.log_debug(f"Site ID: {def_site.id} '{def_site.name}'", def_site)
        script_tag = self.get_tag_auto(commit)
        script_manuf = self.get_manufacturer(commit, set_tag=script_tag)	# условный изготовитель
        script_dev_type = self.get_device_type(commit, set_manufacturer=script_manuf, set_tag=script_tag)
        script_dev_role_pve = self.get_device_role(commit, name=DEVICE_ROLE_PVE, set_tag=script_tag)
        script_dev_role_pbs = self.get_device_role(commit, name=DEVICE_ROLE_PBS, set_tag=script_tag)
        script_vm_role = self.get_device_role(commit, name=VM_DEFAULT_ROLE, set_tag=script_tag)
        script_cluster_type = self.get_cluster_type(commit, set_tag=script_tag)
        script_s_role = self.get_secret_role(commit, name=PROX_SECRET_ROLE, set_tag=script_tag)
# проверяем
        if not (def_site and script_tag and script_manuf and script_dev_type and 
                script_dev_role_pve and script_dev_role_pbs and script_vm_role and script_cluster_type):
            self.log_warning(f"Не созданы необходимые для работы объекты!")
            return

        if script_s_role:
# Получаем UserKey для текущего пользователя из плагина 'netbox_secrets'
            username = self.request.user.username
            my_user = User.objects.get(username=username)
#            self.log_debug(f"User: {username}, id={my_user.id}", my_user)
            try:
                my_ukey = UserKey.objects.get(user=my_user)
#                self.log_debug(f"Active: {my_ukey.is_active()}, Key: {my_ukey.public_key}")
            except:
                self.log_warning(f"Не найден секретный ключ пользователя!", my_user)
                my_ukey = None
# Получаем MasterKey
            if my_ukey and data['key_file']:
#                self.log_debug(f"Key file: {data['key_file'].name} : {data['key_file'].size}")
                priv_key = data['key_file'].read()
#                self.log_debug(f"Private_key: {priv_key}")
                m_key = my_ukey.get_master_key(private_key=priv_key)
#                self.log_debug(f"Master_key: {m_key}")
                if not m_key:
                    self.log_failure(f"Загружен не соответствующий файл ключа!")
            else:
                self.log_warning(f"Не загружен секретный ключ, нет доступа к Proxmox API.")
                m_key = None
        else:
            self.log_warning(f"Не установлен плагин 'netbox_secrets', нет доступа к Proxmox API.")
            m_key = None

# составляем список проверяемых адресов
        ip_list = []
        for subnet in Prefix.objects.all():
            if TAG_AUTO in [tag.name for tag in subnet.tags.all()]:	# только помеченные префиксы
                ip_list.extend(subnet.get_child_ips())
        if len(ip_list)==0:
            self.log_warning(f"Не найдено адресов для сканирования в отмеченных подсетях!")
            return
        self.log_info(f"Проверяем IP: {ip_list[0]} - {ip_list[-1]}")

# основной цикл - перебираем адреса
        for addr in ip_list:
            if str(addr.status).lower() != 'active':	# все активные адреса из списка
                continue
            s_name=addr.dns_name.split('.')[0]		# выбираем хост по DNS-адресу
# проверяем порты Proxmox
            ip4 = str(addr).split('/')[0]
            if self.is_port_open(ip4, PVE_DEFAULT_PORT):
                dev_role = script_dev_role_pve
            elif self.is_port_open(ip4, PBS_DEFAULT_PORT):
                dev_role = script_dev_role_pbs
            else:
# ищем в базе устройство
                s_dev = self.get_device(False, name=s_name, site=def_site)
                if s_dev:		# в списке есть, но Proxmox не отвечает
                    self.log_debug(f"Device '{s_dev.name}' is offline.", s_dev)
                    self.update_device(commit, s_dev, status=DeviceStatusChoices.STATUS_OFFLINE)
                continue		# прочие сервисы на этом адресе игнорируем
# создаем устройство
            s_dev = self.get_device(commit, name=s_name, site=def_site, ipaddr=addr,
                                    status=DeviceStatusChoices.STATUS_ACTIVE,
                                    d_role=dev_role, d_type=script_dev_type, set_tag=script_tag)
            if not s_dev:		# создать не удалось?
                continue
# обновляем устройство
            self.update_device(commit, s_dev, d_role=dev_role, status=DeviceStatusChoices.STATUS_ACTIVE)
# пытаемся подключиться к Proxmox
            prox = self.connect(addr, s_dev, m_key, script_s_role)
            if not prox:
                continue
# смотрим инфу Proxmox и обновляем хосты, интерфейсы, ВМ и прочее
            prox_version = prox.version.get()['version']
            self.log_info(f"Анализ {prox._backend.auth.service} {prox_version} по адресу: {str(addr)}")
            if prox._backend.auth.service==DEVICE_ROLE_PVE:
                p_stat = self.check_pve(commit, prox, addr, site=def_site, set_tag=script_tag)
                self.log_success(f"Анализ PVE '{p_stat['name']}' по адресу: {str(addr)} завершен. Nodes: {p_stat['nodes']}, VMs: {p_stat['vms']}", s_dev)
            else:
                p_stat = self.check_pbs(commit, prox, s_dev, addr, set_tag=script_tag)
                self.log_success(f"Анализ PBS '{p_stat['name']}' по адресу: {str(addr)} завершен.", s_dev)
        return
