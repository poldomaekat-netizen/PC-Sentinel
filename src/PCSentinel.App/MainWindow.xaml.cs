using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
namespace PCSentinel.App;
public partial class MainWindow:Window
{
    private readonly MainViewModel _vm;private readonly System.Windows.Forms.NotifyIcon? _tray;private WidgetWindow? _widget;private bool _quitting;
    public BackdropResult? Backdrop{get;private set;}
    public MainWindow(MainViewModel vm,bool smoke)
    {
        InitializeComponent();_vm=vm;DataContext=vm;
        if(vm.IsTestMode)PreviewMouseDown+=(_,e)=>vm.TraceTestInput($"MouseDown {e.ChangedButton}; source={e.OriginalSource.GetType().Name}; enabled={IsEnabled}; admin={new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)}");
        SourceInitialized+=(_,_)=>ApplyAppearance();vm.SettingsApplied+=ApplyAppearance;vm.AppearancePreview+=PreviewAppearance;
        SystemEvents.UserPreferenceChanged+=PreferencesChanged;
        if(!smoke)
        {
            _tray=new(){Text="PC Sentinel · Glass Edition",Icon=System.Drawing.SystemIcons.Shield,Visible=true};var menu=new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Открыть PC Sentinel",null,(_,_)=>Dispatcher.Invoke(OpenMain));menu.Items.Add("Виджет",null,async(_,_)=>{await ShowWidgetAsync();Hide();});menu.Items.Add("Выход",null,async(_,_)=>await QuitAsync());
            _tray.ContextMenuStrip=menu;_tray.DoubleClick+=(_,_)=>Dispatcher.Invoke(OpenMain);
            vm.Notification+=(title,message)=>_tray.ShowBalloonTip(7000,"PC Sentinel · "+title,message,System.Windows.Forms.ToolTipIcon.Warning);
        }
        Closing+=ClosingWindow;
        Closed+=(_,_)=>{vm.SettingsApplied-=ApplyAppearance;vm.AppearancePreview-=PreviewAppearance;SystemEvents.UserPreferenceChanged-=PreferencesChanged;};
    }
    public void AfterStart(){ApplyAppearance();if(_vm.ActiveSettings.Widget.VisibleOnStartup){_=ShowWidgetAsync(false);Hide();}}
    private void PreferencesChanged(object sender,UserPreferenceChangedEventArgs e)=>Dispatcher.BeginInvoke(new Action(ApplyAppearance));
    private void ApplyAppearance()
    {
        if(_quitting)return;GlassAppearance.UpdateHighContrastPalette();Topmost=_vm.AlwaysOnTop;Backdrop=GlassAppearance.Apply(this,_vm.Settings.BackgroundTransparency);_vm.SetAppearanceStatus(Backdrop.Reason);
        _widget?.ApplyOptions();
        if(_widget!=null){if(_vm.ActiveSettings.Widget.VisibleOnStartup)_widget.Show();else _widget.Hide();}
    }
    private void PreviewAppearance(){Backdrop=GlassAppearance.Apply(this,_vm.Settings.BackgroundTransparency);_vm.SetAppearanceStatus(Backdrop.Reason);_widget?.ApplyGlass();}
    private void OpenMain(){Show();WindowState=WindowState.Normal;Activate();}
    private void ShowSettings(int category=0){OpenMain();Tabs.SelectedIndex=6;if(Tabs.Items[6] is System.Windows.Controls.TabItem tab && tab.Content is SettingsView settings)settings.SelectCategory(category);}
    public void ShowProcess(PCSentinel.Core.ProcessSample sample){OpenMain();Tabs.SelectedIndex=1;ProcessGrid.SelectedItem=_vm.Processes.FirstOrDefault(p=>p.InstanceId==sample.InstanceId);if(ProcessGrid.SelectedItem!=null)ProcessGrid.ScrollIntoView(ProcessGrid.SelectedItem);}
    public async Task ShowWidgetAsync(bool persist=true)
    {
        if(persist)await _vm.UpdateWidgetAsync(w=>w.VisibleOnStartup=true);
        if(_widget==null){_widget=new(_vm,OpenMain,()=>ShowSettings(2),QuitAsync);_widget.Closed+=(_,_)=>_widget=null;}
        _widget.Show();_widget.ApplyOptions();
    }
    private async void ClosingWindow(object? sender,CancelEventArgs e)
    {
        if(_quitting)return;e.Cancel=true;if(_vm.MinimizeToTray && _tray!=null)Hide();else await QuitAsync();
    }
    public async Task QuitAsync()
    {
        if(_quitting)return;_quitting=true;IsEnabled=false;
        try{await _vm.StopAsync();}finally{_tray?.Dispose();_widget?.CloseForShutdown();Close();System.Windows.Application.Current.Shutdown();}
    }
    private async void Compact_Click(object sender,RoutedEventArgs e){await ShowWidgetAsync();Hide();}
    private void Settings_Click(object sender,RoutedEventArgs e)=>ShowSettings();
    private void Minimize_Click(object sender,RoutedEventArgs e)=>WindowState=WindowState.Minimized;
    private void Maximize_Click(object sender,RoutedEventArgs e)=>WindowState=WindowState==WindowState.Maximized?WindowState.Normal:WindowState.Maximized;
    private void Close_Click(object sender,RoutedEventArgs e)=>Close();
    private void CheckIp_Click(object sender,RoutedEventArgs e)=>_vm.RequestManualIpCheck();
    private async void Inventory_Click(object sender,RoutedEventArgs e)=>await _vm.RefreshInventoryAsync();
    private async void Report_Click(object sender,RoutedEventArgs e)=>await _vm.LoadReportAsync();
    internal static bool HasValidationErrors(DependencyObject parent)
    {
        if(System.Windows.Controls.Validation.GetHasError(parent))return true;
        for(var i=0;i<VisualTreeHelper.GetChildrenCount(parent);i++)if(HasValidationErrors(VisualTreeHelper.GetChild(parent,i)))return true;
        return false;
    }
    private async void Export_Click(object sender,RoutedEventArgs e)
    {
        var dialog=new SaveFileDialog{Filter="JSON (*.json)|*.json",FileName=$"PCSentinel-{DateTime.Now:yyyyMMdd-HHmmss}.json",AddExtension=true};
        if(dialog.ShowDialog(this)!=true)return;
        try{await _vm.ExportAsync(dialog.FileName);System.Windows.MessageBox.Show(this,"Экспорт сохранён.","PC Sentinel");}catch(Exception ex){System.Windows.MessageBox.Show(this,ex.Message,"Ошибка экспорта");}
    }
    public async Task CaptureSmokeScreensAsync(string directory)
    {
        async Task Capture(FrameworkElement element,string name)
        {
            element.UpdateLayout();await Dispatcher.InvokeAsync(()=>{},System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            var bitmap=new System.Windows.Media.Imaging.RenderTargetBitmap((int)element.ActualWidth,(int)element.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(element);
            var encoder=new System.Windows.Media.Imaging.PngBitmapEncoder();encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));using var file=System.IO.File.Create(System.IO.Path.Combine(directory,name));encoder.Save(file);
        }
        foreach(var index in new[]{0,1,2,5,6}){Tabs.SelectedIndex=index;await Capture(this,$"ui-tab-{index}.png");}
        if(_vm.Incidents.Count>0){Tabs.SelectedIndex=5;await _vm.SelectIncidentAsync(_vm.Incidents[0]);await Capture(this,"ui-incident-detail.png");}
        var export=new IncidentExportWindow(_vm.Incidents.ToArray()){Owner=this};export.Show();await Capture(export,"ui-export.png");
        await System.IO.File.WriteAllTextAsync(System.IO.Path.Combine(directory,"incidents-redacted.json"),export.PreviewText);
        export.PreviewCsv();await Capture(export,"ui-export-csv.png");await System.IO.File.WriteAllTextAsync(System.IO.Path.Combine(directory,"incidents-redacted.csv"),export.PreviewText);export.Close();
        var originalBackdrop=Backdrop;var fallback=GlassAppearance.Apply(this,0,true);var fallbackAlpha=(ChromeSurface.Background as SolidColorBrush)?.Color.A;
        await System.IO.File.WriteAllTextAsync(System.IO.Path.Combine(directory,"appearance-result.json"),System.Text.Json.JsonSerializer.Serialize(new{Original=originalBackdrop,Fallback=fallback,FallbackAlpha=fallbackAlpha,WindowOpacity=Opacity,CardAlpha=(System.Windows.Application.Current.Resources["Panel"] as SolidColorBrush)?.Color.A},PCSentinel.Storage.LocalStore.Json));
        ApplyAppearance();
        ShowSettings(1);await Capture(this,"ui-settings-vpn.png");
        if(Tabs.Items[6] is System.Windows.Controls.TabItem{Content:SettingsView settings})await settings.CaptureAdapterPopupAsync(element=>Capture(element,"ui-vpn-adapters.png"));
        ShowSettings(2);await Capture(this,"ui-settings-widget.png");
        ShowSettings(3);await Capture(this,"ui-settings-temperatures.png");
        await ShowWidgetAsync();await Capture(_widget!,"ui-widget.png");
        _widget!.ContextMenu.IsOpen=true;await Capture(_widget.ContextMenu,"ui-widget-menu.png");_widget.ContextMenu.IsOpen=false;
        await _vm.UpdateWidgetAsync(w=>{w.Compact=true;w.Topmost=true;w.Locked=true;});await Capture(_widget!,"ui-widget-compact.png");
        var widgetEvidence=new{SharedViewModel=ReferenceEquals(_widget!.DataContext,_vm),Width=_widget.Width,Height=_widget.Height,_widget.Topmost,Locked=_vm.ActiveSettings.Widget.Locked,MainBackdrop=Backdrop,WidgetBackdrop=_widget.Backdrop};
        await System.IO.File.WriteAllTextAsync(System.IO.Path.Combine(directory,"widget-result.json"),System.Text.Json.JsonSerializer.Serialize(widgetEvidence,PCSentinel.Storage.LocalStore.Json));
        await _vm.UpdateWidgetAsync(w=>{w.Compact=false;w.Topmost=false;w.Locked=false;w.VisibleOnStartup=false;});
        Tabs.SelectedIndex=0;Width=720;Height=570;await Capture(this,"ui-narrow.png");Width=960;Height=660;
    }
}
