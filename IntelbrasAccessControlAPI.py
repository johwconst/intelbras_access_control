from ast import Num
from unicodedata import numeric
from numpy import number
import requests
from datetime import datetime
import base64

class IntelbrasAccessControlAPI:
    def __init__(self, ip: str, username: str, passwd: str):
        self.ip = ip   
        self.username = username                            
        self.passwd = passwd
        self.digest_auth = requests.auth.HTTPDigestAuth(self.username, self.passwd)


# Device Manager

    def get_current_time(self) -> datetime:
        try:
            url = "http://{}/cgi-bin/global.cgi?action=getCurrentTime".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()
            
            data = self.raw_to_dict(raw)
                 
            date_time_obj = datetime.strptime(data.get('result').replace("-", "/"), '%Y/%m/%d %H:%M:%S')

            if rval.status_code != 200:
                raise Exception()
            return date_time_obj
        except Exception:
            raise Exception("ERROR - During Get Current Time")
    
    def set_current_time(self) -> str:
        try:
            current_datetime = datetime.today().strftime('%Y-%m-%d') + '%20' + datetime.today().strftime('%H:%M:%S')

            url = "http://{}/cgi-bin/global.cgi?action=setCurrentTime&time={}".format(
                                        str(self.ip),
                                        str(current_datetime), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception:
            raise Exception("ERROR - During Set Current Time")

    def get_software_version(self) -> str:
        try:
            url = "http://{}/cgi-bin/magicBox.cgi?action=getSoftwareVersion".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)
            
            firmware_version = data.get('version')

            if rval.status_code != 200:
                raise Exception()
            return firmware_version
        except Exception:
            raise Exception("ERROR - During Get Software Version")
    
    def get_network_config(self) -> dict:
        try:
            url = "http://{}/cgi-bin/configManager.cgi?action=getConfig&name=Network".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)
            
            network_config_dict = data

            if rval.status_code != 200:
                raise Exception()
            return network_config_dict
        except Exception:
            raise Exception("ERROR - During Get Network Config")
    
    def get_device_serial(self) -> str:
        try:
            url = "http://{}/cgi-bin/magicBox.cgi?action=getSerialNo".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)

            device_serial = data.get('sn')

            if rval.status_code != 200:
                raise Exception()
            return device_serial
        except Exception:
            raise Exception("ERROR - During Get Device Serial")
    
    def get_cgi_version(self) -> str:
        try:
            url = "http://{}/cgi-bin/IntervideoManager.cgi?action=getVersion&Name=CGI".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)

            cgi_version = data.get('version')

            if rval.status_code != 200:
                raise Exception()
            return cgi_version
        except Exception:
            raise Exception("ERROR - During Get CGI Version")
    
    def get_device_type(self) -> str:
        try:
            url = "http://{}/cgi-bin/magicBox.cgi?action=getSystemInfo".format(
                                        str(self.ip), 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)

            device_type = data.get('deviceType')

            if rval.status_code != 200:
                raise Exception()
            return device_type
        except Exception:
            raise Exception("ERROR - During Get CGI Version")
    
    def set_network_config(self, new_ip: str, new_gateway: str, new_mask: str, dhcp: bool) -> str:
        try:
            url = "http://{}/cgi-bin/configManager.cgi?action=setConfig&Network.eth0.IPAddress={}&Network.eth0.DefaultGateway={}&Network.eth0.SubnetMask={}&Network.eth0.DhcpEnable={}".format(
                                        str(self.ip),
                                        str(new_ip),
                                        str(new_gateway),
                                        str(new_mask),
                                        str(dhcp).lower(),
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            
            result = rval.text

            if rval.status_code != 200:
                raise Exception()
            return result
        except Exception:
            raise Exception("ERROR - During Get Software Version")

# Event Server Manager

    def set_event_sender_configuration(self, state: bool, server_address: str, port: number, path: str) -> str:
            '''
            state: True / False
            server_address: Endereço de IP ou DDNS do servidor
            port: Porta do Servidor
            path: Path do servidor, exemplo /notification
            '''
            try:

                url = "http://{}/cgi-bin/configManager.cgi?action=setConfig&PictureHttpUpload.Enable={}&PictureHttpUpload.UploadServerList[0].Address={}&PictureHttpUpload.UploadServerList[0].Port={}&PictureHttpUpload.UploadServerList[0].Uploadpath={}".format(
                                            str(self.ip),
                                            str(state).lower(),
                                            str(server_address),
                                            str(port),
                                            str(path)
                                        )
                    
                rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

                if rval.status_code != 200:
                    raise Exception()
                return str(rval.text)
            except Exception:
                raise Exception("ERROR - During Set Current Time")

# Door Manager

    def open_door(self, door : number) -> str:
        '''
        Send a remote command to open door, default value for door is 1
        '''
        try:
            url = "http://{}/cgi-bin/accessControl.cgi?action=openDoor&channel={}".format(
                                        str(self.ip),
                                        str(door) 
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Open Door - ", e)

    def close_door(self, door : number) -> str:
        '''
        Send a remote command to open close, default value for door is 1
        '''
        try:
            url = "http://{}/cgi-bin/accessControl.cgi?action=closeDoor&channel={}".format(
                                        str(self.ip),
                                        str(door)
                                    )
                
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Close Door - ",e)

    def get_door_state(self, door: number) -> str:
        '''
        Return Close or Open to Door State
        '''
        try:
            url = "http://{}/cgi-bin/accessControl.cgi?action=getDoorStatus&channel=1".format(
                                        str(self.ip),
                                        str(door)
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa
            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)
            
            door_state = data.get('Info.status')

            if rval.status_code != 200:
                raise Exception()
            return str(door_state)
        except Exception as e:
            raise Exception("ERROR - During Get Door State - ", e)

    def set_access_control_door_enable(self, state: bool) -> str:
        try:
            url = "http://{}/cgi-bin/configManager.cgi?action=setConfig&AccessControl[0].Enable={}".format(
                                        str(self.ip),
                                        str(state).lower()
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Enable Door - ",e)
    
    def stop_alarm_v2(self) -> str:
        try:
            url = "http://{}/cgi-bin/configManager.cgi?action=setConfig&AlarmStop.stopAlarm=true".format(
                                        str(self.ip),
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Stop Alarm V2 ",e)

# User Manager

    def delete_all_users_v1(self) -> str:
        '''
        This command delete all user and credential incluse in device
        '''
        try:
            url = "http://{}/cgi-bin/recordUpdater.cgi?action=clear&name=AccessControlCard".format(
                                        str(self.ip)
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Remove All Users using V1 command - ", e)

    def delete_all_users_v2(self) -> str:
        '''
        This command delete all user and credential incluse in device
        '''
        try:
            url = "http://{}/cgi-bin/AccessUser.cgi?action=removeAll".format(
                                        str(self.ip)
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Remove All Users using V2 command - ", e)

    def add_user_v1(self, CardName: str, UserID: number, CardNo: str, CardStatus: number, CardType: number, Password: number, Doors: number) -> dict:
        '''
        CardName: Nome do Usuário / Nome do Cartão
        UserId: Numero de ID do Usuário
        CardNo: Código Hexadecimal do Cartão
        CardStatus:  0 = Normal, 1 = Cancelado, 2 = Congelado
        CardType: 0 = Ordinary card, 1 = VIP card, 2 = Guest card, 3 = Patrol card, 4 = Blocklist card, 5 = Duress card
        Password: Senha de Acesso, Min 4 - Max 6
        Doors: Portas de Acesso, Default 0
        '''
        try:
            url = "http://{}/cgi-bin/recordUpdater.cgi?action=insert&name=AccessControlCard&CardNo={}&CardStatus={}&CardName={}&UserID={}&Password={}&CardType={}&Doors[0]={}".format(
                                        str(self.ip),
                                        str(CardNo).upper(),
                                        str(CardStatus),
                                        str(CardName),
                                        str(UserID),
                                        str(Password),
                                        str(CardType),
                                        str(Doors),
                                    )
            rval = requests.get(url, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            raw = rval.text.strip().splitlines()

            data = self.raw_to_dict(raw)
            
            if rval.status_code != 200:
                raise Exception()
            return data
        except Exception as e:
            raise Exception("ERROR - During Add New User using V1 command - ", e)
  
    def add_user_v2(self, CardName: str, UserID: number, UserType: number, UseTime: number, UserStatus: number, Authority: number) -> str:
        '''
        CardName: Nome do Usuário / Nome do Cartão
        UserId: Numero de ID do Usuário
        UserType: 0 - General user, by default; 1 - Blocklist user (report the blocklist event ACBlocklist); 2 - Guest user; 3 - Patrol user; 4 - VIP user; 5 - Disabled user
        UseTime: Limit of passing times for guest users
        UserStatus: 0 - Normal; 1 - Frozen
        Authority: 1 = Admin; 2 = General user
        '''
        json_cadastro_usuarios = (
            '''{
                    "UserList": [
                        {
                            "UserID": "'''+ str(UserID) +'''",
                            "UserName": "'''+ str(CardName) +'''",
                            "UserType": '''+ str(UserType) +''',
                            "UseTime": '''+ str(UseTime) +''',
                            "UserStatus": '''+ str(UserStatus) +''',
                            "Authority": "'''+ str(Authority) +'''"
                        }
                    ]
                }''' )

        try:
            url = "http://{}/cgi-bin/AccessUser.cgi?action=insertMulti".format(
                                        str(self.ip),
                                    )
            rval = requests.post(url,  data=json_cadastro_usuarios, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            
            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Add New User using V2 command - ", e)

    def update_user_v2(self, CardName: str, UserID: number, UserType: number, UseTime: number, UserStatus: number, Authority: number) -> str:
        '''
        CardName: Nome do Usuário / Nome do Cartão
        UserId: Numero de ID do Usuário
        UserType: 0 - General user, by default; 1 - Blocklist user (report the blocklist event ACBlocklist); 2 - Guest user; 3 - Patrol user; 4 - VIP user; 5 - Disabled user
        UseTime: Limit of passing times for guest users
        UserStatus: 0 - Normal; 1 - Frozen
        Authority: 1 = Admin; 2 = General user
        '''
        json_cadastro_usuarios = (
            '''{
                    "UserList": [
                        {
                            "UserID": "'''+ str(UserID) +'''",
                            "UserName": "'''+ str(CardName) +'''",
                            "UserType": '''+ str(UserType) +''',
                            "UseTime": '''+ str(UseTime) +''',
                            "UserStatus": '''+ str(UserStatus) +''',
                            "Authority": "'''+ str(Authority) +'''"
                        }
                    ]
                }''' )

        try:
            url = "http://{}/cgi-bin/AccessUser.cgi?action=updateMulti".format(
                                        str(self.ip),
                                    )
            rval = requests.post(url,  data=json_cadastro_usuarios, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            
            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Add New User using V2 command - ", e)
       
# Credential Manager

    def add_face(self, UserID: number, image_path: str) -> str:
        '''
        UserID: UserID 
        image_path: Path da imagem
        '''
        with open(str(image_path), "rb") as img_file:
            image_base64 = base64.b64encode(img_file.read())

        json_cadastro_foto = (
            '''{
                "FaceList": [
                    {
                    "UserID": "'''+ str(UserID) +'''",
                    "PhotoData": [
                        "'''+ image_base64.decode('utf-8') +'''"
                    ]
                ]
            }''' )

        try:
            url = "http://{}/cgi-bin/AccessFace.cgi?action=insertMulti".format(
                                        str(self.ip),
                                    )
            rval = requests.post(url,  data=json_cadastro_foto, auth=self.digest_auth, stream=True, timeout=20, verify=False)  # noqa

            
            if rval.status_code != 200:
                raise Exception()
            return str(rval.text)
        except Exception as e:
            raise Exception("ERROR - During Add New User using V2 command - ", e)

    
# FORMAT RETURN

    def raw_to_dict(self, raw):
        data = {}
        for i in raw:
            if len(i) > 1:
                name = i[:i.find("=")]
                val = i[i.find("=") + 1:]
                try:
                    len(data[name])
                except:
                    data[name] = val
            else:
                data["NaN"] = "NaN"
        return data


api = IntelbrasAccessControlAPI('192.168.3.87', 'admin', 'acesso1234')


print(api.stop_alarm_v2())