using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
namespace PCSentinel.App;
public sealed record BackdropResult(bool Applied,bool HighContrast,bool WindowsTransparency,int HResult,int Transparency,string Reason);
public static class GlassAppearance
{
    [StructLayout(LayoutKind.Sequential)]private struct Margins{public int Left,Right,Top,Bottom;}
    [DllImport("dwmapi.dll")]private static extern int DwmSetWindowAttribute(IntPtr hwnd,int attribute,ref int value,int size);
    [DllImport("dwmapi.dll")]private static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd,ref Margins margins);
    [StructLayout(LayoutKind.Sequential)]private struct PowerStatus{public byte AcLine,BatteryFlag,BatteryPercent,EnergySaver;public uint Life,FullLife;}
    [DllImport("kernel32.dll")]private static extern bool GetSystemPowerStatus(out PowerStatus status);
    public static bool TransparencyEnabled()
    {
        try{using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");return key?.GetValue("EnableTransparency") is not int value || value!=0;}catch{return false;}
    }
    public static BackdropResult Apply(Window window,int transparency,bool forceOpaque=false)
    {
        var high=SystemParameters.HighContrast;var enabled=TransparencyEnabled();var hwnd=new WindowInteropHelper(window).Handle;
        var saver=GetSystemPowerStatus(out var power) && power.EnergySaver==1;
        var layered=window.AllowsTransparency;
        var supported=layered || OperatingSystem.IsWindowsVersionAtLeast(10,0,22621);var use=hwnd!=IntPtr.Zero && supported && !high && enabled && !saver && transparency>0 && !forceOpaque;
        var code=-1;
        if(hwnd!=IntPtr.Zero && !layered)
        {
            var dark=1;DwmSetWindowAttribute(hwnd,20,ref dark,4);var rounded=2;DwmSetWindowAttribute(hwnd,33,ref rounded,4);
            var type=use?3:1;code=DwmSetWindowAttribute(hwnd,38,ref type,4);use &= code>=0;
            var margin=new Margins{Left=use?-1:0,Right=use?-1:0,Top=use?-1:0,Bottom=use?-1:0};DwmExtendFrameIntoClientArea(hwnd,ref margin);
            if(HwndSource.FromHwnd(hwnd)?.CompositionTarget is {} target)target.BackgroundColor=use?Colors.Transparent:(high?SystemColors.WindowColor:Color.FromRgb(16,24,33));
        }
        var baseColor=high?SystemColors.WindowColor:Color.FromRgb(16,24,33);
        baseColor.A=use?(byte)Math.Round(255*(1-Math.Clamp(transparency,0,75)/100d)):(byte)255;
        // Paint the alpha surface exactly once. Window.Background must not repeat it.
        window.Background=Brushes.Transparent;
        if(window.Content is System.Windows.Controls.Border surface)surface.Background=new SolidColorBrush(baseColor);
        return new(use,high,enabled,layered?0:code,use?transparency:0,use?(layered?"Per-pixel alpha · фон виджета":"DWM Desktop Acrylic · одна фоновая поверхность"):high?"Высокий контраст":!enabled?"Прозрачность Windows выключена":saver?"Энергосбережение Windows":transparency==0?"Непрозрачность 100%":forceOpaque?"Непрозрачный режим":"DWM недоступен / сборка Windows не поддерживается");
    }
    public static void UpdateHighContrastPalette()
    {
        var high=SystemParameters.HighContrast;var resources=System.Windows.Application.Current.Resources;
        resources["Panel"]=high?SystemColors.WindowBrush:new SolidColorBrush(Color.FromRgb(25,37,50));
        resources["Text"]=high?SystemColors.WindowTextBrush:new SolidColorBrush(Color.FromRgb(241,245,249));
        resources["Muted"]=high?SystemColors.WindowTextBrush:new SolidColorBrush(Color.FromRgb(147,169,188));
        resources["Accent"]=high?SystemColors.HighlightBrush:new SolidColorBrush(Color.FromRgb(36,205,180));
        resources["Field"]=high?SystemColors.ControlBrush:new SolidColorBrush(Color.FromRgb(18,30,41));
        resources["Line"]=high?SystemColors.WindowTextBrush:new SolidColorBrush(Color.FromRgb(48,67,84));
    }
}
