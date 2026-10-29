using PCSentinel.Collectors;
using Xunit;
namespace PCSentinel.IntegrationTests;

public sealed class NativeTemperatureTests
{
    private static byte[] Descriptor(short temperature)
    {
        var data=new byte[40];BitConverter.GetBytes(40u).CopyTo(data,0);BitConverter.GetBytes(40u).CopyTo(data,4);
        BitConverter.GetBytes((ushort)1).CopyTo(data,12);BitConverter.GetBytes(temperature).CopyTo(data,26);return data;
    }
    [Fact]public void StorageCelsiusNeedsNoKelvinConversion()=>Assert.Equal((0,40d),Assert.Single(DirectStorageTemperatureProvider.Parse(Descriptor(40))));
    [Theory][InlineData((short)0)][InlineData(short.MinValue)][InlineData((short)151)]
    public void StorageSentinelAndInvalidTemperatureAreMissing(short value)=>Assert.Empty(DirectStorageTemperatureProvider.Parse(Descriptor(value)));
    [Fact]public void StorageTruncatedDescriptorIsRejected()=>Assert.Empty(DirectStorageTemperatureProvider.Parse(Descriptor(40).AsSpan(0,39)));
    [Fact]public void StorageMalformedCountIsRejected(){var data=Descriptor(40);data[12]=2;Assert.Empty(DirectStorageTemperatureProvider.Parse(data));}
    [Fact]public void StorageUntrustedSizeIsRejected(){var data=Descriptor(40);BitConverter.GetBytes(uint.MaxValue).CopyTo(data,4);Assert.Empty(DirectStorageTemperatureProvider.Parse(data));}
    [Fact]public void IntelPowerTelemetryUsesItsSupportedFlagAndUnits()
    {
        var item=new byte[24];item[0]=1;BitConverter.GetBytes(5).CopyTo(item,4);BitConverter.GetBytes(9).CopyTo(item,8);BitConverter.GetBytes(52.5d).CopyTo(item,16);
        Assert.Equal(52.5,IntelTelemetryTemperature.Parse(item));item[0]=0;Assert.Null(IntelTelemetryTemperature.Parse(item));item[0]=1;item[4]=4;Assert.Null(IntelTelemetryTemperature.Parse(item));
    }
    [Fact]public void IntelPowerTelemetryRejectsNanAndUnknownTypes()
    {
        var item=new byte[24];item[0]=1;item[4]=5;item[8]=9;BitConverter.GetBytes(double.NaN).CopyTo(item,16);Assert.Null(IntelTelemetryTemperature.Parse(item));
        item[8]=10;Assert.Null(IntelTelemetryTemperature.Parse(item));
    }
    [Fact]public void PackageAndGtUseTheirOwnDistanceReadings()
    {
        Assert.Equal(63d,PawnIoTemperatureProvider.Decode(0x80250000,100,127));
        Assert.Equal(46d,PawnIoTemperatureProvider.Decode(0x80360000,100,255));
    }
    [Theory][InlineData(0ul,100)][InlineData(0x00250000ul,100)][InlineData(0xFFFFFFFFul,100)][InlineData(0x80250000ul,0)]
    public void InvalidHardwareDataNeverBecomesARealTemperature(ulong data,int tj)=>Assert.Null(PawnIoTemperatureProvider.Decode(data,tj,127));
}
