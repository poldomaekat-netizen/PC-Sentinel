// Bounded safe diagnostic load: two worker threads for 25 seconds; no network, disk writes or system changes.
var end=System.Diagnostics.Stopwatch.StartNew();
var workers=Enumerable.Range(0,Math.Min(2,Environment.ProcessorCount)).Select(index=>Task.Run(()=>{double value=index+1;while(end.Elapsed.TotalSeconds<25){for(var i=0;i<10000;i++)value=Math.Sqrt(value+1.123456);Thread.SpinWait(100);}return value;})).ToArray();
await Task.WhenAll(workers);Console.WriteLine("Safe load finished after "+end.Elapsed.TotalSeconds.ToString("F1")+" s.");
