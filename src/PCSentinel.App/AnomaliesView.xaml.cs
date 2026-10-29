using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using PCSentinel.Core;
namespace PCSentinel.App;
public partial class AnomaliesView:System.Windows.Controls.UserControl
{
    public AnomaliesView(){InitializeComponent();Loaded+=(_,_)=>{Filter();Vm.PropertyChanged-=VmChanged;Vm.PropertyChanged+=VmChanged;};Unloaded+=(_,_)=>{if(DataContext is MainViewModel vm)vm.PropertyChanged-=VmChanged;};}
    private void VmChanged(object? sender,System.ComponentModel.PropertyChangedEventArgs e){if(e.PropertyName==nameof(MainViewModel.SelectedIncident) && !ReferenceEquals(IncidentGrid.SelectedItem,Vm.SelectedIncident))IncidentGrid.SelectedItem=Vm.SelectedIncident;}
    private MainViewModel Vm=>(MainViewModel)DataContext;
    private void Filter_Changed(object sender,SelectionChangedEventArgs e){if(DataContext!=null)Filter();}
    private void Filter(){if(IncidentGrid==null)return;var view=CollectionViewSource.GetDefaultView(Vm.Incidents);var group=(GroupFilter.SelectedItem as ComboBoxItem)?.Content as string;view.Filter=item=>GroupFilter.SelectedIndex==0 || item is Incident i && i.Group==group;}
    private async void Incident_Changed(object sender,SelectionChangedEventArgs e)=>await Vm.SelectIncidentAsync(IncidentGrid.SelectedItem as Incident);
    private async void Reload_Click(object sender,RoutedEventArgs e)=>await Vm.ReloadIncidentsAsync();
    private async void Context_Click(object sender,RoutedEventArgs e)=>await Vm.SelectIncidentAsync(IncidentGrid.SelectedItem as Incident);
    private async void Expected_Click(object sender,RoutedEventArgs e)=>await Vm.ExpectedAsync();
    private void Process_Click(object sender,RoutedEventArgs e)
    {
        var sample=Vm.SelectedIncident?.Processes.FirstOrDefault()?.Sample;if(sample==null)return;
        if(!Vm.ProcessStillSame(sample)){System.Windows.MessageBox.Show(Window.GetWindow(this),"Этот запуск процесса уже завершён или недоступен. Сохранённые сведения остаются в карточке; текущий владелец PID не используется.","PC Sentinel");return;}
        if(Window.GetWindow(this) is MainWindow main)main.ShowProcess(sample);
    }
    private void Folder_Click(object sender,RoutedEventArgs e)
    {
        var path=Vm.SelectedIncident?.Processes.FirstOrDefault()?.Sample.Path;
        if(path==null || !System.IO.File.Exists(path)){System.Windows.MessageBox.Show("Файл отсутствует или путь недоступен.");return;}
        var start=new ProcessStartInfo(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe")){UseShellExecute=false};start.ArgumentList.Add("/select,"+path);Process.Start(start);
    }
    private async void IgnoreRule_Click(object sender,RoutedEventArgs e)=>await Ignore(false);
    private async void IgnoreProcess_Click(object sender,RoutedEventArgs e)=>await Ignore(true);
    private async Task Ignore(bool process)
    {
        if(Vm.SelectedIncident==null)return;
        if(System.Windows.MessageBox.Show(Window.GetWindow(this),process?"Отключить диагностику этого пути во всех процессных правилах? Это может скрыть будущие аномалии.":"Отключить выбранное правило? Это может скрыть будущие аномалии. Фильтр можно убрать в настройках анализа.","Подтверждение фильтра",MessageBoxButton.YesNo,MessageBoxImage.Warning)==MessageBoxResult.Yes)await Vm.IgnoreAsync(process);
    }
    private void Export_Click(object sender,RoutedEventArgs e)=>new IncidentExportWindow(Vm.Incidents.ToArray()){Owner=Window.GetWindow(this)}.ShowDialog();
}
