namespace PCSentinel.Collectors;

public static class IntelTelemetryTemperature
{
    // ctl_oc_telemetry_item_t: bool at 0, units at 4, scalar type at 8, 8-byte union at 16.
    public static double? Parse(ReadOnlySpan<byte> item)
    {
        if(item.Length<24 || item[0]!=1 || BitConverter.ToInt32(item[4..])!=5)return null;
        var data=item[16..];
        double? value=BitConverter.ToInt32(item[8..]) switch
        {
            0=>(sbyte)data[0],1=>data[0],2=>BitConverter.ToInt16(data),3=>BitConverter.ToUInt16(data),
            4=>BitConverter.ToInt32(data),5=>BitConverter.ToUInt32(data),6=>BitConverter.ToInt64(data),
            7=>BitConverter.ToUInt64(data),8=>BitConverter.ToSingle(data),9=>BitConverter.ToDouble(data),_=>null
        };
        return value is >0 and <=150 && double.IsFinite(value.Value)?value:null;
    }
}
