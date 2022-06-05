
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.stacklayout import StackLayout
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.popup import Popup
from kivy.uix.button import Button
from kivy.properties import StringProperty
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.recycleview import RecycleView
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.label import Label
from kivy.properties import BooleanProperty
from kivy.uix.recycleboxlayout import RecycleBoxLayout
from kivy.uix.behaviors import FocusBehavior
from kivy.uix.recycleview.layout import LayoutSelectionBehavior
from kivy.clock import Clock

externalLog = ""
def logWindow(info):
    global externalLog
    externalLog+=time.strftime('[%Y-%m-%d %H:%M:%S] ',time.localtime())+str(info)+"\n"

class Test(FloatLayout):
    pass
class ScreenRV(Screen):
    pass
class LabelBlack(Label):
    pass
class DeviceList(BoxLayout):
    pass
class CommandButton(Button):
    def __init__(self,device_id,command,info, **kwargs):
        super().__init__(**kwargs)
        self.device_id =device_id
        self.command = command
        self.text = self.command+"\n"+info

    def on_press(self):
        sendDeviceCommand(self.device_id,self.command)
        return super().on_press()

class MainWindow(Screen):
    def popup(self):
        show_popup()
    def refresh(self):
        getCertNode()
    pass
import threading
class DeviceWindow(Screen):
    log_info = StringProperty('')
    def __init__(self, device_id=None,**kw):
        super(DeviceWindow, self).__init__(**kw)
        self.device_id = device_id
        self.ids.lable_title.text = "当前设备："+str(device_id)
        Clock.schedule_interval(self.update_log,0.2)
        Clock.schedule_interval(self.update_status,1)
        self.CLevent = Clock.schedule_interval(self.updateCommandList,1)
        self.connect_device()
    def on_leave(self):
        screen_manager.remove_widget(self)
    def update_log(self,dt):
        self.log_info = externalLog
    def connect_device(self):
        global externalLog
        changeExternalLogWindow(logWindow)
        externalLog = "正在尝试连接...\n"
        threading.Thread(target=userConnectHandler, args=(self.device_id,)).start()    
        pass
    def refresh(self):
        self.connect_device()
        self.updateCommandList()
    def updateCommandList(self,dt=None):
        commandArea = self.ids.commandArea
        commandArea.clear_widgets()
        if self.device_id in commandList:
            self.CLevent.cancel()
            for k,v in commandList[self.device_id].items():
                commandArea.add_widget(CommandButton(device_id = self.device_id, command = k,info = v['info']))
    def update_status(self,dt):
        if self.device_id in deviceStatus:
            self.ids.lable_status.text = ""
            for k,v in deviceStatus[self.device_id].items():
                self.ids.lable_status.text+="\n"+str(k)+": "+str(v)
import time

def userConnectHandler(device_id):
    logWindow("收到对"+device_id+"的连接请求")
    conn = checkIDConnection(device_id,logger = logWindow)
    if not conn:
        if userEstablishHandler(device_id,logger = logWindow):
            logWindow("建立连接成功")
        else:
            logWindow("建立连接失败")
    else:
        getDeviceInfo(device_id)
class WindowManager(ScreenManager):
    pass


class P(FloatLayout):
    pass
def show_popup(): 
    
    show = P()
    popupWindow = Popup(title="Popup",content=show,size_hint=(None,None),size=(400,400))
    popupWindow.open()


class DeviceLable(StackLayout):
    id = StringProperty("ID")
    name = StringProperty("Name")
    role = StringProperty("Role")
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    pass

class SelectableRecycleBoxLayout(FocusBehavior, LayoutSelectionBehavior,
                                 RecycleBoxLayout):
    ''' Adds selection and focus behaviour to the view. '''


class SelectableLabel(RecycleDataViewBehavior, DeviceLable):
    ''' Add selection support to the Label '''
    index = None
    selected = BooleanProperty(False)
    selectable = BooleanProperty(True)

    def refresh_view_attrs(self, rv, index, data):
        ''' Catch and handle the view changes '''
        self.index = index
        return super(SelectableLabel, self).refresh_view_attrs(
            rv, index, data)

    def on_touch_up(self,touch):
        if super(SelectableLabel, self).on_touch_up(touch):
            return True
        if self.collide_point(*touch.pos) and self.selectable:
            return self.parent.select_with_touch(self.index, touch)
        

    def apply_selection(self, rv, index, is_selected):
        ''' Respond to the selection of items in the view. '''
        self.selected = is_selected
        if is_selected:
            #connectToID(rv.data[index]['id'])
            # App.get_running_app().root.ids.asas.device_id = rv.data[index]['id']
            dev_window = DeviceWindow(device_id=rv.data[index]['id'],name = rv.data[index]['id'])
            screen_manager.add_widget(dev_window)
            screen_manager.current = rv.data[index]['id']
            screen_manager.transition.direction = "left"
            self.parent.clear_selection()
            print("selection changed to {0}".format(rv.data[index]))


class RV(RecycleView):
    def __init__(self, **kwargs):
        super(RV, self).__init__(**kwargs)
        Clock.schedule_interval(self.update_deviceList,0.5)
    def update_deviceList(self,dt):
        #self.data = [{'id': str(x),'id': str(x),'name':"adax"} for x in range(int(str(time.time())[-3:-2]),12)]
        self.data = [{
            'id': k,
            'name':v[2]['name'],
            'role':str(v[2]['role'])}
            for k,v in networkList.items()]

screen_manager = None
class MainApp(App):
    def build(self):
        global screen_manager
        screen_manager = WindowManager()
        return screen_manager

if __name__ == '__main__':
    from user import *
    
    MainApp().run()