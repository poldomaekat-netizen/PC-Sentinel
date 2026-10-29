using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text.Json;
namespace PCSentinel.App;
public partial class MainWindow
{
    // Explicit test mode only. Copies the actual composed desktop, never RenderTargetBitmap.
    public async Task CaptureDesktopAcceptanceAsync(string directory)
    {
        var board=new Window{Title="PC Sentinel · локальный контрастный фон для проверки",WindowStyle=WindowStyle.None,ResizeMode=ResizeMode.NoResize,ShowInTaskbar=false,WindowState=WindowState.Maximized};
        var drawing=new DrawingGroup();drawing.Children.Add(new GeometryDrawing(new SolidColorBrush(Color.FromRgb(240,214,150)),null,new RectangleGeometry(new Rect(0,0,160,160))));
        drawing.Children.Add(new GeometryDrawing(new SolidColorBrush(Color.FromRgb(12,92,130)),null,new RectangleGeometry(new Rect(0,0,80,80))));drawing.Children.Add(new GeometryDrawing(new SolidColorBrush(Color.FromRgb(12,92,130)),null,new RectangleGeometry(new Rect(80,80,80,80))));
        var brush=new DrawingBrush(drawing){TileMode=TileMode.Tile,ViewportUnits=BrushMappingMode.Absolute,Viewport=new Rect(0,0,160,160)};
        board.Content=new Border{Background=brush,Child=new TextBlock{Text="PC SENTINEL — КОНТРАСТНЫЙ ТЕСТ ПРОСВЕЧИВАНИЯ\nЭто окно служит фоном; системные обои не изменены.",FontSize=20,Margin=new Thickness(25),Foreground=Brushes.White,VerticalAlignment=VerticalAlignment.Bottom}};
        var mainTransparency=_vm.Settings.BackgroundTransparency;var widgetTransparency=_vm.Settings.Widget.BackgroundTransparency;var wasTopmost=Topmost;
        try
        {
            board.Show();await Task.Delay(300);Show();WindowState=WindowState.Normal;Width=900;Height=650;Left=70;Top=65;Tabs.SelectedIndex=0;Topmost=true;
            await ShowWidgetAsync(false);_widget!.Topmost=true;
            var screen=System.Windows.Forms.Screen.PrimaryScreen!;var dpi=VisualTreeHelper.GetDpi(this);
            _widget.Left=(screen.WorkingArea.Right/dpi.DpiScaleX)-_widget.Width-35;_widget.Top=80;
            var results=new List<object>();
            foreach(var amount in new[]{0,25,75})
            {
                _vm.Settings.BackgroundTransparency=amount;_vm.Settings.Widget.BackgroundTransparency=amount;PreviewAppearance();Activate();await Task.Delay(800);
                var area=System.Windows.Forms.SystemInformation.VirtualScreen;
                using var bitmap=new System.Drawing.Bitmap(area.Width,area.Height,System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                using(var graphics=System.Drawing.Graphics.FromImage(bitmap))graphics.CopyFromScreen(area.Left,area.Top,0,0,area.Size,System.Drawing.CopyPixelOperation.SourceCopy);
                bitmap.Save(Path.Combine(directory,$"desktop-transparency-{amount}.png"),System.Drawing.Imaging.ImageFormat.Png);
                results.Add(new{Requested=amount,Main=Backdrop,Widget=_widget.Backdrop,WindowOpacity=Opacity,WidgetOpacity=_widget.Opacity,WidgetAllowsTransparency=_widget.AllowsTransparency,MainSurfaceAlpha=(ChromeSurface.Background as SolidColorBrush)?.Color.A,WidgetSurfaceAlpha=(_widget.Content as Border)?.Background is SolidColorBrush b?b.Color.A:0,DesktopWidth=area.Width,DesktopHeight=area.Height,DpiX=dpi.PixelsPerInchX});
            }
            await File.WriteAllTextAsync(Path.Combine(directory,"desktop-acceptance.json"),JsonSerializer.Serialize(results,PCSentinel.Storage.LocalStore.Json));
            if(_vm.Incidents.Count>0){Tabs.SelectedIndex=5;await _vm.SelectIncidentAsync(_vm.Incidents[0]);Activate();await Task.Delay(500);var area=System.Windows.Forms.SystemInformation.VirtualScreen;using var bitmap=new System.Drawing.Bitmap(area.Width,area.Height);using(var g=System.Drawing.Graphics.FromImage(bitmap))g.CopyFromScreen(area.Left,area.Top,0,0,area.Size);bitmap.Save(Path.Combine(directory,"desktop-incidents.png"));}
        }
        finally{_vm.Settings.BackgroundTransparency=mainTransparency;_vm.Settings.Widget.BackgroundTransparency=widgetTransparency;Topmost=wasTopmost;_widget?.Hide();board.Close();Width=960;Height=660;PreviewAppearance();}
    }
}
