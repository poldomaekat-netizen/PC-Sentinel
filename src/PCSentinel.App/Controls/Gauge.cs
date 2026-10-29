using System.Globalization;
using System.Windows;
using System.Windows.Media;

namespace PCSentinel.App.Controls;

public sealed class Gauge : FrameworkElement
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(nameof(Value), typeof(double), typeof(Gauge), new FrameworkPropertyMetadata(double.NaN, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty LabelProperty = DependencyProperty.Register(nameof(Label), typeof(string), typeof(Gauge), new FrameworkPropertyMetadata("N/A", FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(nameof(Caption), typeof(string), typeof(Gauge), new FrameworkPropertyMetadata("СЕЙЧАС", FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty WarningProperty = DependencyProperty.Register(nameof(Warning), typeof(double), typeof(Gauge), new FrameworkPropertyMetadata(60d, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty CriticalProperty = DependencyProperty.Register(nameof(Critical), typeof(double), typeof(Gauge), new FrameworkPropertyMetadata(85d, FrameworkPropertyMetadataOptions.AffectsRender));
    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public string Label { get => (string)GetValue(LabelProperty); set => SetValue(LabelProperty, value); }
    public string Caption { get => (string)GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }
    public double Warning { get => (double)GetValue(WarningProperty); set => SetValue(WarningProperty, value); }
    public double Critical { get => (double)GetValue(CriticalProperty); set => SetValue(CriticalProperty, value); }
    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        var size = Math.Min(ActualWidth, ActualHeight); var r = Math.Max(1, size / 2 - 12); var center = new Point(ActualWidth / 2, ActualHeight / 2);
        DrawArc(dc, center, r, 1, new SolidColorBrush(Color.FromRgb(41, 54, 74)), 9);
        var brush = double.IsNaN(Value) ? new SolidColorBrush(Color.FromRgb(103, 122, 148)) : Value >= Critical ? Brushes.Salmon : Value >= Warning ? Brushes.Goldenrod : new SolidColorBrush(Color.FromRgb(86, 218, 181));
        if (!double.IsNaN(Value) && Value > 0) DrawArc(dc, center, r, Math.Clamp(Value / 100, 0.001, 1), brush, 9);
        var text = new FormattedText(Label, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI Semibold"), Math.Clamp(size*0.235,11,30), SystemParameters.HighContrast?SystemColors.WindowTextBrush:new SolidColorBrush(Color.FromRgb(241,245,249)), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(text, new(center.X - text.Width / 2, center.Y - text.Height / 2));
        var sub = new FormattedText(Caption, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), Math.Clamp(size*0.065,6,9), new SolidColorBrush(Color.FromRgb(147,169,188)), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(sub, new(center.X - sub.Width / 2, center.Y + size*0.17));
    }
    private static void DrawArc(DrawingContext dc, Point center, double r, double fraction, Brush brush, double width)
    {
        Point At(double degree) { var a = degree * Math.PI / 180; return new(center.X + r * Math.Cos(a), center.Y + r * Math.Sin(a)); }
        var geometry = new StreamGeometry(); using (var ctx = geometry.Open())
        { ctx.BeginFigure(At(135), false, false); ctx.ArcTo(At(135 + 270 * fraction), new Size(r,r), 0, fraction > 2d/3, SweepDirection.Clockwise, true, false); }
        var pen = new Pen(brush, width) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round }; dc.DrawGeometry(null, pen, geometry);
    }
}
