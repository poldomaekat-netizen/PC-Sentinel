using System.Windows;
using System.Windows.Controls;
namespace PCSentinel.App;
public partial class SettingsView: System.Windows.Controls.UserControl
{
    public SettingsView(){InitializeComponent();Loaded+=(_,_)=>{MonitorList.ItemsSource=new[]{new MonitorOption("","Авто / ближайший")}.Concat(System.Windows.Forms.Screen.AllScreens.Select(s=>new MonitorOption(s.DeviceName,s.DeviceName+(s.Primary?" · основной":""))));UpdateMode();};}
    private MainViewModel Vm=>(MainViewModel)DataContext;
    private async void EnableHardwareTemperatures_Click(object sender,RoutedEventArgs e)
    {((Button)sender).IsEnabled=false;try{await Vm.EnableHardwareTemperaturesAsync();}finally{((Button)sender).IsEnabled=true;}}
    private async void DisableHardwareTemperatures_Click(object sender,RoutedEventArgs e)=>await Vm.DisableHardwareTemperaturesAsync();
    private void Transparency_Changed(object sender,RoutedPropertyChangedEventArgs<double> e){if(IsLoaded && DataContext is MainViewModel vm)Dispatcher.BeginInvoke(vm.PreviewGlass);}
    private async void TrustCurrent_Click(object sender,RoutedEventArgs e)
    {
        var ip=Vm.CurrentConfirmedIpv4;if(ip==null){Vm.SetMessage("Сначала получите свежие согласованные ответы: «Проверить сейчас».");return;}
        if(System.Windows.MessageBox.Show(Window.GetWindow(this),$"Сохранить {ip} как доверенный IPv4? Совпадение адреса не доказывает защиту VPN.","Подтвердить доверенный IP",MessageBoxButton.YesNo,MessageBoxImage.Question)!=MessageBoxResult.Yes)return;
        Vm.Settings.TrustedPublicIp=ip;await Vm.SaveSettingsAsync();Vm.RequestManualIpCheck();Vm.RefreshIpTrust();
    }
    private void RemoveIgnore_Click(object sender,RoutedEventArgs e){if(IgnoreRules.SelectedItem is string rule)Vm.Settings.Anomalies.IgnoredRules.Remove(rule);if(IgnorePaths.SelectedItem is string path)Vm.Settings.Anomalies.IgnoredPaths.Remove(path);IgnoreRules.Items.Refresh();IgnorePaths.Items.Refresh();}
    public void SelectCategory(int index)=>SettingsNav.SelectedIndex=index;
    internal async Task CaptureAdapterPopupAsync(Func<FrameworkElement,Task> capture)
    {
        var original=AutoMode.IsChecked;AutoMode.IsChecked=false;ManualAdapter.ApplyTemplate();ManualAdapter.IsDropDownOpen=true;
        try
        {
            await Dispatcher.InvokeAsync(()=>{},System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            if(ManualAdapter.Template.FindName("PART_Popup",ManualAdapter) is System.Windows.Controls.Primitives.Popup{Child:FrameworkElement child})await capture(child);
        }
        finally{ManualAdapter.IsDropDownOpen=false;AutoMode.IsChecked=original;}
    }
    private void Mode_Changed(object sender,RoutedEventArgs e)=>UpdateMode();
    private void UpdateMode(){if(ManualAdapter!=null){ManualAdapter.IsEnabled=AutoMode?.IsChecked!=true;ManualAdapter.Visibility=AutoMode?.IsChecked==true?Visibility.Collapsed:Visibility.Visible;}}
    private async void Save_Click(object sender,RoutedEventArgs e)
    {if(MainWindow.HasValidationErrors(this)){Vm.SetMessage("Исправьте числовые значения.");return;}await Vm.SaveSettingsAsync();}
    private void Check_Click(object sender,RoutedEventArgs e)=>Vm.RequestManualIpCheck();
    private async void Remember_Click(object sender,RoutedEventArgs e)=>await Vm.CaptureVpnProfileAsync();
    private void AddSite_Click(object sender,RoutedEventArgs e){try{Vm.AddSite(NewSite.Text);SiteList.Items.Refresh();NewSite.Clear();}catch(Exception ex){Vm.SetMessage(ex.Message);}}
    private void RemoveSite_Click(object sender,RoutedEventArgs e)
    {
        if(SiteList.SelectedItem is not PCSentinel.Core.SiteTarget site)return;
        if(new[]{"google.com","yandex.ru","cloudflare.com"}.Contains(new Uri(site.Url).Host)){Vm.SetMessage("Предустановленный сайт можно отключить флажком.");return;}
        Vm.Settings.ControlSites.Remove(site);SiteList.Items.Refresh();
    }
    public record MonitorOption(string Id,string Label);
}
