using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using PCSentinel.Core;
namespace PCSentinel.App;
public sealed class IncidentExportWindow:Window
{
    private readonly IReadOnlyList<Incident> _items;
    private readonly System.Windows.Controls.TextBox _preview=new(){AcceptsReturn=true,AcceptsTab=true,TextWrapping=TextWrapping.NoWrap,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Auto,FontFamily=new("Consolas")};
    private readonly System.Windows.Controls.CheckBox _paths=new(){Content="Включить пути и имена пользователя (могут быть чувствительными)"};
    private readonly System.Windows.Controls.CheckBox _ips=new(){Content="Включить IP-адреса"};
    private readonly System.Windows.Controls.ComboBox _format=new(){ItemsSource=new[]{"JSON","CSV"},SelectedIndex=0,Width=100};
    public IncidentExportWindow(IReadOnlyList<Incident> items)
    {
        _items=items;Style=(Style)System.Windows.Application.Current.FindResource(typeof(Window));Title="Экспорт инцидентов · проверьте и отредактируйте данные";Width=850;Height=650;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        var root=new DockPanel{Margin=new Thickness(16)};Content=root;var top=new StackPanel();DockPanel.SetDock(top,Dock.Top);root.Children.Add(top);
        top.Children.Add(new TextBlock{Text="Локальный файл. Перед сохранением можно удалить чувствительные данные из текста.",TextWrapping=TextWrapping.Wrap});top.Children.Add(_paths);top.Children.Add(_ips);
        var bar=new StackPanel{Orientation=System.Windows.Controls.Orientation.Horizontal};top.Children.Add(bar);bar.Children.Add(_format);var generate=new System.Windows.Controls.Button{Content="Пересоздать предпросмотр"};generate.Click+=(_,_)=>Generate();bar.Children.Add(generate);var save=new System.Windows.Controls.Button{Content="Сохранить…"};save.Click+=Save;bar.Children.Add(save);root.Children.Add(_preview);
        _format.SelectionChanged+=(_,_)=>Generate();_paths.Checked+=(_,_)=>Generate();_paths.Unchecked+=(_,_)=>Generate();_ips.Checked+=(_,_)=>Generate();_ips.Unchecked+=(_,_)=>Generate();Generate();
    }
    internal string PreviewText=>_preview.Text;
    internal void PreviewCsv()=>_format.SelectedIndex=1;
    private string Redact(string text)=>ExportRedaction.Apply(text,_paths.IsChecked==true,_ips.IsChecked==true,Environment.UserName);
    private void Generate()
    {
        var node=JsonSerializer.SerializeToNode(_items)!;
        void Walk(JsonNode? n)
        {
            if(n is JsonObject o)foreach(var p in o.ToArray()){if(p.Value is JsonValue v && v.TryGetValue<string>(out var text))o[p.Key]=Redact(text);else Walk(p.Value);}
            else if(n is JsonArray a)foreach(var v in a)Walk(v);
        }
        Walk(node);
        if(_format.SelectedIndex==0)_preview.Text=node.ToJsonString(new(){WriteIndented=true,Encoder=System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All)});
        else
        {
            string Csv(string text){if(text.Length>0 && "=+-@".Contains(text[0]))text="'"+text;return "\""+text.Replace("\"","\"\"")+"\"";}
            var rows=new List<string>{"id,startedUtc,endedUtc,rule,severity,source,confidence,expected,peakCpu,peakRam,peakDiskActive,peakNetworkBps,peakTemperature,reason,processInstances,paths"};
            foreach(var i in _items)rows.Add(string.Join(",",new[]{i.Id,i.StartedUtc.ToString("O"),i.EndedUtc?.ToString("O")??"",i.Rule,i.Severity,Redact(i.Source),Redact(i.Confidence),i.Expected.ToString(),i.PeakCpu?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"",i.PeakRam?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"",i.PeakIo?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"",i.PeakNetwork?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"",i.PeakTemperature?.ToString(System.Globalization.CultureInfo.InvariantCulture)??"",Redact(i.Reason),string.Join("; ",i.Processes.Select(p=>$"{p.Sample.Name}|{p.Sample.Pid}|{p.Sample.StartTimeUtc:O}")),Redact(string.Join("; ",i.Processes.Select(p=>p.Sample.Path??"—")))}.Select(Csv)));
            _preview.Text=string.Join(Environment.NewLine,rows);
        }
    }
    private async void Save(object sender,RoutedEventArgs args)
    {
        var csv=_format.SelectedIndex==1;var dialog=new Microsoft.Win32.SaveFileDialog{Filter=csv?"CSV (*.csv)|*.csv":"JSON (*.json)|*.json",FileName="PCSentinel-incidents."+(csv?"csv":"json")};if(dialog.ShowDialog(this)!=true)return;
        try{if(!csv)JsonNode.Parse(_preview.Text);await System.IO.File.WriteAllTextAsync(dialog.FileName,_preview.Text,new System.Text.UTF8Encoding(true));Close();}catch(Exception e){System.Windows.MessageBox.Show(this,e.Message,"Ошибка экспорта");}
    }
}
