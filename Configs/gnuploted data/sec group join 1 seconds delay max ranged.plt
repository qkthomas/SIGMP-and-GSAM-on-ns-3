set terminal svg
set output "sec group join 1 seconds delay max ranged.svg"
set title "sec group join 2-D Plot, joins with dealy smaller than 1 seconds"
set xlabel "Nth GM Join (20 GMs, 2 NQs, 20% Rejection, Link: 100mbps, 10ms)"
set ylabel "Delay in Seconds"

set yrange [0:+1]
set term svg mouse jsdir "http://gnuplot.sourceforge.net/demo_svg/"
plot "-"  title "46 joins, average delay: 0.183785 seconds" with linespoints
0 0.23756
1 0.243194
2 0.175774
3 0.192655
4 0.0502493
5 0.101289
6 0.188054
7 0.18289
8 0.19372
9 0.1818
10 0.16631
11 0.234843
12 0.0502753
13 0.101447
14 0.0709313
15 0.182816
16 0.17348
17 0.0506243
18 0.111343
19 0.111788
20 0.265525
21 0.319054
22 0.240208
23 0.163199
24 0.938249
25 0.163087
26 0.161685
27 0.235553
28 0.183807
29 0.332527
30 0.150887
31 0.0510743
32 0.185566
33 0.0502573
34 0.21271
35 0.170003
36 0.171549
37 0.101197
38 0.100826
39 0.164561
40 0.17874
41 0.0709203
42 0.0708383
43 0.182763
44 0.168258
45 0.420014
e
