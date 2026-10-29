using System.Windows;
using System.Windows.Controls;
namespace PCSentinel.App.Controls;
public sealed class AdaptivePanel:Panel
{
    private int _columns=3;private double _height=153;
    protected override Size MeasureOverride(Size available)
    {
        var width=double.IsInfinity(available.Width)?900:available.Width;
        _columns=width>=760?3:width>=480?2:1;
        _height=0;foreach(UIElement child in InternalChildren){child.Measure(new(width/_columns,double.PositiveInfinity));_height=Math.Max(_height,child.DesiredSize.Height);}
        return new(width,Math.Ceiling(InternalChildren.Count/(double)_columns)*_height);
    }
    protected override Size ArrangeOverride(Size final)
    {for(var i=0;i<InternalChildren.Count;i++)InternalChildren[i].Arrange(new Rect(i%_columns*final.Width/_columns,i/_columns*_height,final.Width/_columns,_height));return final;}
}
