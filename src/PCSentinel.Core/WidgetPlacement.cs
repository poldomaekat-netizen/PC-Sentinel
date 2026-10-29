namespace PCSentinel.Core;
public readonly record struct WorkArea(double Left,double Top,double Width,double Height);
public readonly record struct WidgetBounds(double Left,double Top,double Width,double Height);
public static class WidgetPlacement
{
    public static WidgetBounds Place(WorkArea area,WidgetBounds box,string dock)
    {
        var width=Math.Min(box.Width,area.Width);var height=Math.Min(box.Height,area.Height);var margin=12d;
        var left=box.Left;var top=box.Top;
        if(dock is "TopLeft" or "BottomLeft" or "Left")left=area.Left+margin;
        if(dock is "TopRight" or "BottomRight" or "Right")left=area.Left+area.Width-width-margin;
        if(dock is "TopLeft" or "TopRight" or "Top")top=area.Top+margin;
        if(dock is "BottomLeft" or "BottomRight" or "Bottom")top=area.Top+area.Height-height-margin;
        return new(Math.Clamp(left,area.Left,area.Left+area.Width-width),Math.Clamp(top,area.Top,area.Top+area.Height-height),width,height);
    }
}
