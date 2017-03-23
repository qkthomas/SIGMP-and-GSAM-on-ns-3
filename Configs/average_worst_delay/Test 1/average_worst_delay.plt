set terminal svg
set output "average_worst_delay.svg"
set title "Average And Worst Delay VS Rejection Histogram, 10 GMs, Join Interval:10sec"
set ylabel "Delay in Seconds"
set xlabel "Percentage of Rejection"
set term svg mouse jsdir "http://gnuplot.sourceforge.net/demo_svg/"
set style data histogram
set style histogram clustered gap 1
set style fill solid 0.4 border
plot "average_worst_delay.dat" using 2:xticlabels(1) title columnheader(2), '' using 3:xticlabels(1) title columnheader(3), '' using 4:xticlabels(1) title columnheader(4), '' using 5:xticlabels(1) title columnheader(5), '' using 6:xticlabels(1) title columnheader(6), '' using 7:xticlabels(1) title columnheader(7), '' using 8:xticlabels(1) title columnheader(8), '' using 9:xticlabels(1) title columnheader(9)
