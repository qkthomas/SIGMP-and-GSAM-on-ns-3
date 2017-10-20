set terminal svg
set output "average_worst_delay.svg"
set title "Average And Worst Delay VS Rejection Histogram, 10 GMs, Join Interval:10sec"
set ylabel "Delay in Seconds"
set xlabel "Percentage of Rejection"
set term svg mouse jsdir "http://gnuplot.sourceforge.net/demo_svg/"
set style data histogram
set style histogram clustered gap 1
set style fill solid 0.2 border
#plot "average_worst_delay.dat" using 2:xticlabels(1):2 with labels title columnheader(2), '' using 3:xticlabels(1):3 with labels title columnheader(3)
STARTCOL = 2
ENDCOL = 9
plot for [COL=STARTCOL:ENDCOL] 'average_worst_delay.dat' using COL:xticlabels(1) title columnheader(COL)
