from pysnmp import hlapi
from pysnmp.error import PySnmpError
import time
import traceback
from datetime import datetime
import sys
# pylint: disable=unused-wildcard-import
from .const import * 
# pylint: enable=unused-wildcard-import
import threading
import time
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity import Entity

from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_IP_ADDRESS,
    EVENT_HOMEASSISTANT_STOP, 
    CONF_SCAN_INTERVAL,
)


async def async_setup_entry(hass, config_entry,async_add_entities):
    """Set up the sensor platform."""
    LOGGER.info('SETUP_ENTRY')
    #username=config_entry.data.get(CONF_USERNAME)
    #password=config_entry.data.get(CONF_PASSWORD)
    ipaddress=config_entry.data.get(CONF_IP_ADDRESS)
    updateIntervalSeconds=config_entry.options.get(CONF_SCAN_INTERVAL)
    maxretries=3
    
    for i in range(maxretries):
        try:
            monitor = SnmpStatisticsMonitor(ipaddress,updateIntervalSeconds,async_add_entities)
            break
        except:
            if i==maxretries-1:
                raise


        
        
    hass.data[DOMAIN][config_entry.entry_id]={"monitor":monitor}
    
    
    monitor.start()
    def _stop_monitor(_event):
        monitor.stopped=True
    #hass.states.async_set
    hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, _stop_monitor)
    LOGGER.info('Init done')
    return True


class SnmpStatisticsSensor(Entity):
    def __init__(self,id,name=None):
        self._attributes = {}
        self._state ="NOTRUN"
        self.entity_id=id
        if name is None:
            name=id
        self._name=name
        LOGGER.info("Create Sensor {0}".format(id))

    def set_state(self, state):
        """Set the state."""
        if self._state==state:
            return
        self._state = state
        if self.enabled:
            self.schedule_update_ha_state()


    def set_attributes(self, attributes):
        """Set the state attributes."""
        self._attributes = attributes

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this sensor."""
        return self.entity_id


    @property
    def should_poll(self):
        """Only poll to update phonebook, if defined."""
        return False
    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return self._attributes
    @property
    def state(self):
        """Return the state of the device."""
        return self._state
    @property
    def name(self):
        """Return the name of the sensor."""
        return self._name
    def update(self):
        LOGGER.info("update "+self.entity_id)

class SnmpStatisticsMonitor:

    def __init__(self,target_ip,updateIntervalSeconds=1,async_add_entities=None):
        self.meterSensors={}
        self.stopped = False
        self.async_add_entities=async_add_entities
        self.updateIntervalSeconds=updateIntervalSeconds
        self.current_if_data={}
        self.current_if_data_time=0
        self.stat_time=0
        self.target_ip=target_ip
        self.hostname=None
        self.cpuload1=None
        self.cpuload2=None
        self.cpuload3=None
        self.update_stats()#try this to throw error if not working.
        if async_add_entities is not None:
            self.setupEntities()

    #region static methods
    @staticmethod
    def get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.getCmd(
            engine,
            credentials,
            hlapi.UdpTransportTarget((target, port)),
            context,
            *__class__.construct_object_types(oids)
        )
        return __class__.fetch(handler, 1)[0]
    
    @staticmethod
    def construct_object_types(list_of_oids):
        object_types = []
        for oid in list_of_oids:
            object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
        return object_types

    @staticmethod
    def get_bulk(target, oids, credentials, count, start_from=0, port=161,
                engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.bulkCmd(
            engine,
            credentials,
            hlapi.UdpTransportTarget((target, port)),
            context,
            start_from, count,
            *__class__.construct_object_types(oids)
        )
        return __class__.fetch(handler, count)

    @staticmethod
    def get_bulk_auto(target, oids, credentials, count_oid, start_from=0, port=161,
                    engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        count = __class__.get(target, [count_oid], credentials, port, engine, context)[count_oid]
        return __class__.get_bulk(target, oids, credentials, count, start_from, port, engine, context)
    @staticmethod
    def cast(value):
        try:
            return int(value)
        except (ValueError, TypeError):
            try:
                return float(value)
            except (ValueError, TypeError):
                try:
                    return str(value)
                except (ValueError, TypeError):
                    pass
        return value
    @staticmethod
    def fetch(handler, count):
        result = []
        for i in range(count):
            try:
                error_indication, error_status, error_index, var_binds = next(handler)
                if not error_indication and not error_status:
                    items = {}
                    for var_bind in var_binds:
                        items[str(var_bind[0])] = __class__.cast(var_bind[1])
                    result.append(items)
                else:
                    raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
            except StopIteration:
                break
        return result

    #endregion
    def update_stats(self):
        self.update_netif_stats()
        more_data=__class__.get(self.target_ip,[
            '1.3.6.1.2.1.1.5.0',
            '1.3.6.1.4.1.2021.10.1.3.1',
            '1.3.6.1.4.1.2021.10.1.3.2',
            '1.3.6.1.4.1.2021.10.1.3.3',
            ],hlapi.CommunityData('public'))
        
        
        #cpu usage://1.3.6.1.2.1.25.3.3[.1...4]
        cpu_usages= __class__.get_bulk(self.target_ip, [
            '1.3.6.1.2.1.25.3.3',
        ], hlapi.CommunityData('public', mpModel=1), 
            32 
        )

        
        #print(more_data)
        #print(more_data['1.3.6.1.4.1.2021.10.1.1'])
        #print(more_data['1.3.6.1.2.1.1.5.0'])
        #for k,v in more_data:
        #    print(f"{k}:{v}")
        self.hostname=more_data['1.3.6.1.2.1.1.5.0']
        self.cpuload1=more_data['1.3.6.1.4.1.2021.10.1.3.1']
        self.cpuload2=more_data['1.3.6.1.4.1.2021.10.1.3.2']
        self.cpuload3=more_data['1.3.6.1.4.1.2021.10.1.3.3']

    def update_netif_stats(self):
        if_data=self.current_if_data
        its = __class__.get_bulk_auto(self.target_ip, [
            '1.3.6.1.2.1.2.2.1.2',#v1, ifDescr
            #'1.3.6.1.2.1.2.2.1.16',#v1, ifOutOctets
            #'1.3.6.1.2.1.2.2.1.10',#v1, ifInOctets
            '1.3.6.1.2.1.31.1.1.1.1',#v2, ifName
            '1.3.6.1.2.1.31.1.1.1.18',#v2, ifAlias
            '1.3.6.1.2.1.31.1.1.1.6', #v2, ifHCInOctets
            '1.3.6.1.2.1.31.1.1.1.10', #v2, ifHCOutOctets
        ], hlapi.CommunityData('public', mpModel=1), 
            '1.3.6.1.2.1.2.1.0' #v1, ifCount
        )

        

        for k in if_data:
            if_data[k]['rx_octets_prev']=if_data[k]['rx_octets']
            if_data[k]['tx_octets_prev']=if_data[k]['tx_octets']



        for it in its:
            for k, v in it.items():
                oidParts=k.split('.')
                ifId=oidParts[-1]
                infotype=oidParts[-2]
                if ifId not in if_data:
                    if_data[ifId]={
                        'name':'',
                        'name2':'',
                        'alias':'',
                        'rx_octets':-1,
                        'tx_octets':-1,
                        'rx_speed_octets':-1.0,
                        'tx_speed_octets':-1.0,
                        'rx_octets_prev':-1.0,
                        'tx_octets_prev':-1.0,
                        'last_stat_time':time.time(),
                        'rx_diff':-1,
                        'tx_diff':-1
                        }
                
                if infotype=='2':
                    if_data[ifId]['name']=v
                elif infotype=='1':
                    if_data[ifId]['name2']=v
                elif infotype=='18':
                    if_data[ifId]['alias']=v
                elif k.find('2.2.1.10')>-1:
                    if_data[ifId]['rx_octets']=v
                elif k.find('2.2.1.16')>-1:
                    if_data[ifId]['tx_octets']=v
                elif k.find('31.1.1.1.6')>-1:
                    if_data[ifId]['rx_octets']=v
                elif k.find('31.1.1.1.10')>-1:
                    if_data[ifId]['tx_octets']=v


        new_if_data_time=time.time()
        for k in self.current_if_data:
            cur_data=self.current_if_data[k]
            
            timediff_statistics=new_if_data_time-cur_data['last_stat_time']
            timediff_stat_seconds=timediff_statistics#/1000.0

            rx_diff=cur_data['rx_octets']-cur_data['rx_octets_prev']
            tx_diff=cur_data['tx_octets']-cur_data['tx_octets_prev']


            cur_data['rx_diff']=rx_diff
            cur_data['tx_diff']=tx_diff

            if timediff_stat_seconds<1:
                continue

            if rx_diff==0 and tx_diff==0 and timediff_stat_seconds<4:##wait until really going to 0
                continue

            rx_byte_s=rx_diff/timediff_stat_seconds
            tx_byte_s=tx_diff/timediff_stat_seconds
            cur_data['last_stat_time']=new_if_data_time

            cur_data['rx_speed_octets']=rx_byte_s
            cur_data['tx_speed_octets']=tx_byte_s


        self.current_if_data=if_data
        self.current_if_data_time=new_if_data_time

    def start(self):
        threading.Thread(target=self.watcher).start()
    def watcher(self):
        LOGGER.info(f'Start Watcher Thread - updateInterval:{self.updateIntervalSeconds}')

        while not self.stopped:
            try:
                #LOGGER.warning('Get PowerMeters: ')
                self.update_stats()
                if self.async_add_entities is not None:
                    self.AddOrUpdateEntities()
            except (KeyError,PySnmpError):
                time.sleep(1)#sleep a second for these errors
            except:#other errors get logged...
                e = traceback.format_exc()
                LOGGER.error(e)
            if self.updateIntervalSeconds is None:
                self.updateIntervalSeconds=5

            time.sleep(max(1,self.updateIntervalSeconds))

    #region HA
    def setupEntities(self):
        self.update_stats()
        if self.async_add_entities is not None:
            self.AddOrUpdateEntities()

    
    def _AddOrUpdateEntity(self,id,friendlyname,value,unit):
        if id in self.meterSensors:
            sensor=self.meterSensors[id]
            #sensor.set_attributes({"unit_of_measurement":unit,"device_class":"power","friendly_name":friendlyname})
            sensor.set_state(value)
        else:
            sensor=SnmpStatisticsSensor(id,friendlyname)
            sensor._state=value
            sensor.set_attributes(
                    {
                        "unit_of_measurement":unit,
                        #"device_class":"power",
                        "friendly_name":friendlyname
                    }
                )
            self.async_add_entities([sensor])
            #time.sleep(.5)#sleep a moment and wait for async add
            self.meterSensors[id]=sensor
        
    def AddOrUpdateEntities(self):
        allSensorsPrefix="sensor."+DOMAIN+"_"+self.target_ip.replace('.','_')+"_"
        for k in self.current_if_data:
            cur_if_data=self.current_if_data[k]
            if_name=cur_if_data['name2']
            if_alias=cur_if_data['alias']

            if_rx_mbit=cur_if_data['rx_speed_octets']*8/1000/1000
            if_tx_mbit=cur_if_data['tx_speed_octets']*8/1000/1000
            if_rx_mbyte=cur_if_data['rx_speed_octets']/1000/1000
            if_tx_mbyte=cur_if_data['tx_speed_octets']/1000/1000



            if_rx_total_mbit=cur_if_data['rx_octets']*8/1000/1000
            if_tx_total_mbit=cur_if_data['tx_octets']*8/1000/1000


            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_curbw_out_mbit',if_name+" BW Out (mbit)",round(if_tx_mbit,2),'mbit/s')
            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_curbw_in_mbit',if_name+" BW In (mbit)",round(if_rx_mbit,2),'mbit/s')

            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_curbw_out_mbyte',if_name+" BW Out (mbyte)",round(if_tx_mbyte,2),'mbyte/s')
            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_curbw_in_mbyte',if_name+" BW In (mbyte)",round(if_rx_mbyte,2),'mbyte/s')


            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_total_out_mbit',if_name+" Total Out (mbit)",round(if_tx_total_mbit,2),'mbit')
            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_total_in_mbit',if_name+" Total In (mbit)",round(if_rx_total_mbit,2),'mbit')
            
            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_total_out_byte',if_name+" Total Out (bytes)",cur_if_data['tx_octets'],'byte')
            self._AddOrUpdateEntity(allSensorsPrefix+"netif_"+if_name+'_total_in_byte',if_name+" Total In (bytes)",cur_if_data['rx_octets'],'byte')



        self._AddOrUpdateEntity(allSensorsPrefix+"cpu_load_1","CPU Avg 1",self.cpuload1*100,'%')
        self._AddOrUpdateEntity(allSensorsPrefix+"cpu_load_2","CPU Avg 2",self.cpuload2*100,'%')
        self._AddOrUpdateEntity(allSensorsPrefix+"cpu_load_3","CPU Avg 3",self.cpuload3*100,'%')
        



