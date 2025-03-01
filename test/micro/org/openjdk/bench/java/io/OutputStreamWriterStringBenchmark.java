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
public class OutputStreamWriterStringBenchmark {

    @Param({"US-ASCII", "ISO-8859-1", "UTF-8", "UTF-16"})
    private String charsetName;

    @Param({"1", "10", "100", "1000", "10000"})
    private int stringLength;

    private Writer osw;

    private String ascii;

    private String latin1;

    private String bmp;

    @Setup
    public void setup(Blackhole bh) throws UnsupportedEncodingException {
        OutputStream bos = new BlackholedOutputStream(bh);
        osw = new OutputStreamWriter(bos, charsetName);
        ascii = "a".repeat(stringLength);
        latin1 = "\u00F6".repeat(stringLength);
        bmp = "\u20AC".repeat(stringLength);
    }

    @Benchmark
    public void writeAsciiString() throws IOException {
        osw.write(ascii);
        osw.flush();
    }

    @Benchmark
    public void writeLatin1String() throws IOException {
        osw.write(latin1);
        osw.flush();
    }

    @Benchmark
    public void writeBmpString() throws IOException {
        osw.write(bmp);
        osw.flush();
    }

}
