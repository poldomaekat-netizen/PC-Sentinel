using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
using PCSentinel.Core;
namespace PCSentinel.App;
public partial class WidgetWindow:Window
{
    private readonly MainViewModel _vm;private readonly Action _openMain,_settings;private readonly Func<Task> _quit;private bool _shutdown,_placing;
    public BackdropResult? Backdrop{get;private set;}
    [StructLayout(LayoutKind.Sequential)]private struct Rect{public int Left,Top,Right,Bottom;}
    [DllImport("user32.dll")]private static extern bool GetWindowRect(IntPtr hwnd,out Rect rect);
    [DllImport("user32.dll")]private static extern bool SetWindowPos(IntPtr hwnd,IntPtr after,int x,int y,int width,int height,uint flags);
    public WidgetWindow(MainViewModel vm,Action openMain,Action settings,Func<Task> quit)
    {
        InitializeComponent();_vm=vm;_openMain=openMain;_settings=settings;_quit=quit;DataContext=vm;
        SourceInitialized+=(_,_)=>ApplyOptions();SystemEvents.DisplaySettingsChanged+=DisplaysChanged;
        ContextMenu=new System.Windows.Controls.ContextMenu();ContextMenu.Opened+=(_,_)=>BuildMenu();
        Closing+=async(_,e)=>{if(!_shutdown){e.Cancel=true;Hide();await _vm.UpdateWidgetAsync(w=>w.VisibleOnStartup=false);}};
        Closed+=(_,_)=>SystemEvents.DisplaySettingsChanged-=DisplaysChanged;
    }
    public void ApplyOptions()
    {
        _placing=true;
        try
        {
            var w=_vm.ActiveSettings.Widget;Topmost=w.Topmost;Width=(w.Compact?260:320)*w.Scale;Height=(w.Compact?197:242)*w.Scale;
            PinButton.Content=w.Locked?"◆":"◇";NetworkBand.Visibility=w.ShowNetwork?Visibility.Visible:Visibility.Collapsed;VpnBand.Visibility=w.ShowVpn?Visibility.Visible:Visibility.Collapsed;
            ApplyGlass();PlaceOnScreen();
        }
        finally{_placing=false;}
    }
    public void ApplyGlass()=>Backdrop=GlassAppearance.Apply(this,_vm.Settings.Widget.BackgroundTransparency);
    private void PlaceOnScreen()
    {
        var hwnd=new WindowInteropHelper(this).Handle;if(hwnd==IntPtr.Zero)return;
        var w=_vm.ActiveSettings.Widget;GetWindowRect(hwnd,out var rect);
        var screens=System.Windows.Forms.Screen.AllScreens;
        var screen=screens.FirstOrDefault(s=>s.DeviceName==w.MonitorDevice)??System.Windows.Forms.Screen.FromPoint(new System.Drawing.Point((int)w.Left,(int)w.Top));
        var area=screen.WorkingArea;
        var box=WidgetPlacement.Place(new(area.Left,area.Top,area.Width,area.Height),new(w.Left,w.Top,Math.Max(1,rect.Right-rect.Left),Math.Max(1,rect.Bottom-rect.Top)),w.Dock);
        SetWindowPos(hwnd,IntPtr.Zero,(int)box.Left,(int)box.Top,(int)box.Width,(int)box.Height,0x14);
    }
    private void DisplaysChanged(object? sender,EventArgs e)=>Dispatcher.BeginInvoke(()=>{if(!_shutdown)PlaceOnScreen();});
    private async void Widget_MouseDown(object sender,MouseButtonEventArgs e)
    {
        if(_placing || e.ChangedButton!=MouseButton.Left)return;
        for(var node=e.OriginalSource as DependencyObject;node!=null;node=node is Visual?VisualTreeHelper.GetParent(node):LogicalTreeHelper.GetParent(node))if(node is System.Windows.Controls.Primitives.ButtonBase)return;
        if(e.ClickCount==2){_openMain();e.Handled=true;return;}
        if(_vm.ActiveSettings.Widget.Locked)return;
        try{DragMove();}catch(InvalidOperationException){return;}
        var hwnd=new WindowInteropHelper(this).Handle;GetWindowRect(hwnd,out var r);
        var screen=System.Windows.Forms.Screen.FromHandle(hwnd);var a=screen.WorkingArea;
        var box=WidgetPlacement.Place(new(a.Left,a.Top,a.Width,a.Height),new(r.Left,r.Top,r.Right-r.Left,r.Bottom-r.Top),"None");
        // Snap to a nearby edge after dragging, then persist physical desktop coordinates.
        var atLeft=Math.Abs(box.Left-a.Left)<18;var atRight=Math.Abs(box.Left+box.Width-a.Right)<18;
        var atTop=Math.Abs(box.Top-a.Top)<18;var atBottom=Math.Abs(box.Top+box.Height-a.Bottom)<18;
        var dock=atLeft&&atTop?"TopLeft":atRight&&atTop?"TopRight":atLeft&&atBottom?"BottomLeft":atRight&&atBottom?"BottomRight":atLeft?"Left":atRight?"Right":atTop?"Top":atBottom?"Bottom":"None";
        await _vm.UpdateWidgetAsync(w=>{w.Left=box.Left;w.Top=box.Top;w.MonitorDevice=screen.DeviceName;w.Dock=dock;});
    }
    private async void Pin_Click(object sender,RoutedEventArgs e)=>await _vm.UpdateWidgetAsync(w=>w.Locked=!w.Locked);
    private async void Hide_Click(object sender,RoutedEventArgs e){Hide();await _vm.UpdateWidgetAsync(w=>w.VisibleOnStartup=false);}
    private void BuildMenu()
    {
        var menu=ContextMenu;menu.Items.Clear();var w=_vm.ActiveSettings.Widget;
        void Item(string header,Action action,bool? check=null){var item=new MenuItem{Header=header,IsCheckable=check.HasValue,IsChecked=check??false};item.Click+=(_,_)=>action();menu.Items.Add(item);}
        Item("Открыть главную панель",_openMain);Item("Поверх всех окон",async()=>await _vm.UpdateWidgetAsync(x=>x.Topmost=!x.Topmost),w.Topmost);
        Item("Закрепить положение",async()=>await _vm.UpdateWidgetAsync(x=>x.Locked=!x.Locked),w.Locked);Item("Настроить виджет",_settings);
        var monitors=new MenuItem{Header="Выбрать монитор"};foreach(var screen in System.Windows.Forms.Screen.AllScreens){var item=new MenuItem{Header=screen.DeviceName,IsCheckable=true,IsChecked=screen.DeviceName==w.MonitorDevice};item.Click+=async(_,_)=>await _vm.UpdateWidgetAsync(x=>{x.MonitorDevice=screen.DeviceName;x.Dock="TopRight";});monitors.Items.Add(item);}menu.Items.Add(monitors);
        Item("Автозапуск",async()=>await _vm.UpdateAutoStartAsync(!_vm.ActiveSettings.AutoStart),_vm.ActiveSettings.AutoStart);
        Item("Свернуть в трей",()=>Hide_Click(this,new()));Item("Выход",async()=>await _quit());
    }
    public void CloseForShutdown(){_shutdown=true;Close();}
}
