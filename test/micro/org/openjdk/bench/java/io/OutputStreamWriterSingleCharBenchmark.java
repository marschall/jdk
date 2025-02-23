package org.openjdk.bench.java.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Fork(2)
@Warmup(iterations = 4, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 2, timeUnit = TimeUnit.SECONDS)
@State(Scope.Thread)
public class OutputStreamWriterSingleCharBenchmark {

    @Param({"US-ASCII", "ISO-8859-1", "ISO-8859-6", "UTF-8", "UTF-16", "MS932"})
    private String charsetName;

    private Writer osw;

    @Setup
    public void setup(Blackhole bh) throws UnsupportedEncodingException {
        OutputStream bos = new BlackholedOutputStream(bh);
        osw = new OutputStreamWriter(bos, charsetName);
    }

    @Benchmark
    public void writeAscii() throws IOException {
        osw.write('a');
        osw.flush();
    }

    @Benchmark
    public void writeLatin1() throws IOException {
        osw.write('\u00F6');
        osw.flush();
    }
    
    @Benchmark
    public void writeArabic() throws IOException {
        osw.write('\u0621');
        osw.flush();
    }
    
    @Benchmark
    public void writeKatakana() throws IOException {
        osw.write('\u3044');
        osw.flush();
    }

}
