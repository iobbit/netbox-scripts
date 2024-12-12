import requests
import re
from extras.scripts import Script, BooleanVar, StringVar
from tenancy.models import Contact, ContactGroup
from extras.models import CustomField

TEL_ID = 'tel_id'	# наименование поля - идентификатора привязки

# Подразделение - словарь: {
#	'str_id': '831',	идентификатор записи в тел.справочнике
#	'str_name': 'Департамент внутренней политики и развития местного самоуправления Орловской области',
#	'str_parent': '0',	идентификатор вышестоящего подразделения
#	'adres': '302021, г. Орёл, пл. Ленина, д. 1',
#	'mail': 'depvp@adm.orel.ru'
#}
# Сотрудник - словарь: {
#'	'str_id': '831',	идентификатор подразделения
#	'ppl_id': '3455',	идентификатор записи в тел.справочнике
#	'ppl_fio': 'Трифонова Ольга Николаевна',
#	'dlg_name': 'заместитель руководителя Департамента',
#	'ppl_tel': ':598332',
#	'ppl_cab': '407'
#}

class ContactImport(Script):
    # можно отключить разные блоки импорта
    ImportOrg = BooleanVar(
        label="Смотреть структуру?",
        default=True,
        description="Включить просмотр организационной структуры (подразделений)",
    )
    ImportPerson = BooleanVar(
        label="Смотреть состав?",
        default=True,
        description="Включить просмотр сотрудников",
    )
    # установка URL тел.справочника
    API_URL = StringVar(
        max_length=50,
        label="Адрес справочника",
        default="http://telefon.head.adm/exp.php",
        description="Укажите адрес источника данных для программного доступа",
        required=True,
    )

    class Meta:
        name = "Contacts import script"
        description = "Просматривает телефонный справочник и обновляет списки 'Contact Groups' и 'Contacts'"
        commit_default = True
        job_timeout = 300

    def run(self, data, commit):

        try:
            tel_id = CustomField.objects.get(name=TEL_ID)	# проверка нужного для работы CustomField
        except:
            self.log_failure(f"Нет добавочного (custom) поля: '{TEL_ID}'")
            return
#        self.log_debug(tel_id)

        try:		# запрос в телефонный справочник
            response = requests.get(str(data['API_URL'])).json()	# забираем сразу всё
        except:
            self.log_failure(f"Ошибка получения данных. Проверьте адрес источника: {data['API_URL']}")
            return
        self.log_debug(f"список структур: {len(response['str'])}, список должностей: {len(response['ppl'])}")

        if data['ImportOrg']:
            self.log_info(f"Проверка существующих групп.")
            for grp in ContactGroup.objects.all():		# сначала обновляем подразделения
                if grp.cf[TEL_ID]:				# только перенесенные из справочника
                    self.manage_grp(commit, grp, response['str'])
            self.log_info(f"Обновление структуры по справочнику.")
            for org in response['str']:
                self.manage_org(commit, org)			# добавляем недостающие

        if data['ImportPerson']:
            self.log_info(f"Проверка существующих контактов.")
            for cont in Contact.objects.all():			# обновляем сотрудников
                if cont.cf[TEL_ID]:				# только перенесенные из справочника
                    self.manage_cont(commit, cont, response['ppl'])
            self.log_info(f"Обновление контактов по справочнику.")
            for sotr in response['ppl']:
                self.manage_person(commit, sotr)		# добавляем новых

        return

    def make_slug(self, grp_id):		# уникальный URL-friendly идентификатор для создаваемых групп
        return f'grp{grp_id}'

    def make_description(self, adres, mail):	# описание группы составляем из адреса и эл.почты
        return f"{str(adres) if adres else ''}{'; Email: '+str(mail) if mail else ''}"	# Null не допускается, только пустые строки

    def find_parent(self, grp_id):		# поиск вышестоящей группы (если есть)
        try:
            parent = ContactGroup.objects.get(custom_field_data = dict({TEL_ID:grp_id}))
        except ContactGroup.DoesNotExist:
            parent = None
        return parent

    def find_org_name(self, org_name, struct):	# поиск групп по имени в тел.справочнике (если есть)
        t2s = []				# возвращаем список
        for item in struct:
            if org_name == item['str_name']:
                t2s.append(item)
        return t2s

    def find_pers_name(self, p_name, struct):	# поиск человека по имени в тел.справочнике (если есть)
        t2s = []				# возвращаем список
        for item in struct:
            if p_name == item['ppl_fio']:
                t2s.append(item)
        return t2s

    def get_item(self, collection, key, target):	# поиск в списке словарей по ключу
        return next((item for item in collection if item[key] == target), False)

    def manage_grp(self, commit, grp, struct):		# обработка группы в netbox
#        self.log_debug(f"Группа: id={grp.cf[TEL_ID]}, {grp.name}")
        n_org = self.get_item(struct, 'str_id', grp.cf[TEL_ID])	# ищем группу по id в справочнике
        if not n_org:						# удалена из структуры
            self.log_debug(f"Группа: id={grp.cf[TEL_ID]} {grp.name} не найдена!")
            t_grp = self.find_org_name(grp.name, struct)	# ищем группу по имени в справочнике (список)
            if len(t_grp) == 0:
                self.log_success(f"Удаляем группу !!! id={grp.cf[TEL_ID]} {grp.name}")
                if commit:
                    try:
                        grp.delete()
                    except:
                        self.log_failure(f"Ошибка удаления группы id={grp.cf[TEL_ID]} {grp.name}")
            elif len(t_grp) == 1:	# подразделение переподчинили
                self.log_debug(f"Найдена группа: id={t_grp[0]['str_id']}, {t_grp[0]['str_name']}.")
                if ((grp.cf[TEL_ID] != t_grp[0]['str_id']) or (grp.parent != self.find_parent(t_grp[0]['str_parent']))):
                    self.log_success(f"Обновляем группу: id={grp.cf[TEL_ID]} {grp.name} -> ID: {t_grp[0]['str_id']}, Parent: {t_grp[0]['str_parent']}")
                    if commit:
                        if grp.pk and hasattr(grp, 'snapshot'):
                            grp.snapshot()			# запись для истории изменений
                        grp.custom_field_data = dict({TEL_ID:t_grp[0]['str_id']})
                        grp.parent = self.find_parent(t_grp[0]['str_parent'])
                        grp.full_clean()
                        grp.save()
            elif len(t_grp) > 1:	# есть несколько новых подразделений с такими же именами - что делать?
                id2s = []
                for item in t_grp:
                    id2s.append(item['str_id'])
                self.log_warning(f"Найдены группы {grp.name}: {id2s}")
        return

    def manage_org(self, commit, unit):			# обработка группы в тел.справочнике
#        self.log_debug(f"Подразделение: id={unit['str_id']}, {unit['str_name']}")
        try:
            grp = ContactGroup.objects.get(custom_field_data = dict({TEL_ID:unit['str_id']}))
            self.log_debug(f"Найдена группа: id={grp.cf[TEL_ID]} {grp.name}, Parent: {grp.parent}, Desc: {grp.description}")
# значения из тел.справочника
            tel_grp = [ unit['str_name'], self.make_slug(unit['str_id']), self.find_parent(unit['str_parent']), self.make_description(unit['adres'], unit['mail']) ]
            if (grp.name != tel_grp[0]) or (grp.slug != tel_grp[1]) or (grp.parent != tel_grp[2]) or (grp.description != tel_grp[3]):
                self.log_success(f"Обновляем группу: id={grp.cf[TEL_ID]} {tel_grp[0]}, Parent: {tel_grp[2]}, Desc: {tel_grp[3]}")
                if commit:
                    if grp.pk and hasattr(grp, 'snapshot'):
                        grp.snapshot()				# запись для истории изменений
                    grp.name = tel_grp[0]
                    grp.slug = tel_grp[1]
                    grp.parent = tel_grp[2]
                    grp.description = tel_grp[3]
                    grp.full_clean()
                    grp.save()
        except ContactGroup.DoesNotExist:
            new_gpr = ContactGroup(
                name = unit['str_name'],
                slug = self.make_slug(unit['str_id']),
                parent = self.find_parent(unit['str_parent']),
                description = self.make_description(unit['adres'], unit['mail']),
                custom_field_data = dict({TEL_ID:unit['str_id']}),	# ключевое поле
                )
            self.log_success(f"Добавляем новую группу: id={unit['str_id']} {unit['str_name']}")
            if commit:
                try:
                    new_gpr.full_clean()
                    new_gpr.save()
                except:
                    self.log_failure(f"Ошибка создания ContactGroup {new_grp.name} в группе {new_grp.parent}")
        return

    def make_phone(self, tel_num):		# очищаем номер телефона - только цифры
        return re.sub(r'\D', '', tel_num)

    def manage_person(self, commit, sotr):
#        self.log_debug(f"Сотрудник: id={sotr['ppl_id']}, {sotr['ppl_fio']}")
        if not sotr['ppl_fio']:		# вакансии без ФИО не записываем
            return
        try:
            pers = Contact.objects.get(custom_field_data = dict({TEL_ID:sotr['ppl_id']}))
            self.log_debug(f"Найден сотрудник: id={pers.cf[TEL_ID]} {pers.name}, Group: {pers.group}, Title: {pers.title}")
# значения из тел.справочника
            ppl = [ sotr['ppl_fio'], sotr['dlg_name'], self.find_parent(sotr['str_id']), sotr['ppl_cab'], self.make_phone(sotr['ppl_tel']) ]
            if (pers.name != ppl[0]) or (pers.title != ppl[1]) or (pers.group != ppl[2]) or (pers.address != ppl[3]) or (pers.phone != ppl[4]):
                self.log_success(f"Обновляем сотрудника: id={pers.cf[TEL_ID]} {ppl[0]}, Group: {ppl[2]}, Title: {ppl[1]}, Addr: {ppl[3]}, Phone: {ppl[4]}")
                if commit:
                    if pers.pk and hasattr(pers, 'snapshot'):
                        pers.snapshot()				# запись для истории изменений
                    pers.name = ppl[0]
                    pers.title = ppl[1]
                    pers.group = ppl[2]
                    pers.address = ppl[3]
                    pers.phone = ppl[4]
                    pers.full_clean()
                    pers.save()
        except Contact.DoesNotExist:
            new_pers = Contact(
                name = sotr['ppl_fio'],
                title = sotr['dlg_name'],
                group = self.find_parent(sotr['str_id']),
                address = sotr['ppl_cab'],
                phone = self.make_phone(sotr['ppl_tel']),
                custom_field_data = dict({TEL_ID:sotr['ppl_id']}),	# ключевое поле
                )
            self.log_success(f"Добавляем сотрудника: id={sotr['ppl_id']} {sotr['ppl_fio']} в {sotr['str_id']}")
            if commit:
                try:
                    new_pers.full_clean()
                    new_pers.save()
                except:
                    self.log_failure(f"Ошибка создания Contact {new_pers.name} в группе {new_pers.group}")
        return

    def manage_cont(self, commit, cont, tel_list):
#        self.log_debug(f"Контакт: id={cont.cf[TEL_ID]}, {cont.name}")
        pers = self.get_item(tel_list, 'ppl_id', cont.cf[TEL_ID])	# ищем человека по id в справочнике
        if not pers:
            self.log_debug(f"Контакт: id={cont.cf[TEL_ID]} {cont.name} не найден!")
            names = self.find_pers_name(cont.name, tel_list)		# ищем по имени контакта в справочнике (список)
            if len(names) == 0:
                self.log_success(f"Удаляем контакт !!! id={cont.cf[TEL_ID]} {cont.name}")
                if commit:
                    try:
                        cont.delete()
                    except:
                        self.log_failure(f"Ошибка удаления контакта id={cont.cf[TEL_ID]} {cont.name}")
            elif len(names) == 1:	# сотрудника перевели в другое подразделение
                self.log_debug(f"Найден сотрудник: id={names[0]['ppl_id']}, {names[0]['ppl_fio']}.")
                if ((cont.cf[TEL_ID] != names[0]['ppl_id']) or (cont.group != self.find_parent(names[0]['str_id']))):
                    self.log_success(f"Обновляем контакт: id={cont.cf[TEL_ID]} {cont.name} grp={cont.group} -> ID: {names[0]['ppl_id']}, Parent: {names[0]['str_id']}")
                    if commit:
                        try:
                            if cont.pk and hasattr(cont, 'snapshot'):
                                cont.snapshot()			# запись для истории изменений
                            cont.custom_field_data = dict({TEL_ID:names[0]['ppl_id']})
                            cont.group = self.find_parent(names[0]['str_id'])
                            cont.full_clean()
                            cont.save()
                        except:
                            self.log_failure(f"Ошибка обновления контакта id={cont.cf[TEL_ID]} {cont.name} grp={cont.group}")
            elif len(names) > 1:	# есть несколько новых с такими же ФИО - что делать?
                id2s = []
                for item in names:
                    id2s.append(item['ppl_id'])
                self.log_warning(f"Найдены сотрудники {cont.name}: {id2s}")
        return
