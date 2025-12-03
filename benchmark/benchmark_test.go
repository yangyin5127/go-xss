package xss

import (
	"io/ioutil"
	"testing"
	"time"

	// "fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/yangyin5127/go-xss"
)

func cpu() {
	cpuprofile := "./cpuprofile.cp"
	// 打开处理器 profile 文件
	f, _ := os.Create(cpuprofile)

	pprof.StartCPUProfile(f)
}

func BenchmarkSpeed(b *testing.B) {

	runtime.GOMAXPROCS(1)

	file := "./index.html"
	content, _ := ioutil.ReadFile(file)

	html := string(content)

	options := xss.XssOption{}
	x := xss.NewXSS(options)

	// num:=10
	b.ResetTimer()
	// cpu()

	t1 := time.Now()
	for i := 0; i < b.N; i++ {
		// fmt.Sprintf("%d",num)
		x.Process(html)
	}
	t2 := time.Now()
	// defer pprof.StopCPUProfile()

	b.Logf("xss total time: %v %d %d", t2.Sub(t1), b.N, len(html))

	ts := float64(len(html)*b.N) / t2.Sub(t1).Seconds() / (1024 * 1024)

	b.Logf("xss处理速度 %f MB/s", ts)

}
