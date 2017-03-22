set terminal svg
set output "worst_delay.svg"
set title "Worst Delay Histogram"
set ylabel "Delay in Seconds"
set term svg mouse jsdir "http://gnuplot.sourceforge.net/demo_svg/"
set style data histogram
set style histogram clustered gap 1
set style fill solid 0.4 border
plot "worst_delay.dat" using 2:xticlabels(1) title columnheader(2), '' using 3:xticlabels(1) title columnheader(3), '' using 4:xticlabels(1) title columnheader(4), '' using 5:xticlabels(1) title columnheader(5)