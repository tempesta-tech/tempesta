/**
 *		Tempesta FW
 *
 * Simple linear regression calculation on sliding data window.
 * This model assumes time as explanatory variable @x.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <assert.h>

#include <iostream>

template<class T, const long wsz>
class SLR {
	// Use the multiplier to calculate @y with 1/MUL
	// precision on integer arithmetic. */
	static const long MUL	= 1000;

	long n; /* observation number */
	T x_avg, y_avg;
	T xy_avg; /* avg(x * y) */
	T x_avg_y_avg; /* avg(x) * avg(y) */
	T x_sq_avg; /* avg(x * x) */
	T x_avg_sq; /* avg(x) * avg(x) */
	T a, b; /* coefficients for y = a + b*x + eps */
	struct {
		T x;
		T y;
	} win[wsz];

public:
	SLR()
		: n(0), x_avg(0), y_avg(0), xy_avg(0), x_avg_y_avg(0),
		x_sq_avg(0), x_avg_sq(0), a(0), b(0), win{0}
	{}

	void
	slr_upd(long x, long y)
	{
		int ni, sz;

		y *= MUL;
		x *= MUL;
		ni = n % wsz;

		if (n < wsz) {
			sz = ni + 1;
			x_avg = (x_avg * n + x) / sz;
			y_avg = (y_avg * n + y) / sz;
			xy_avg = (xy_avg * n + y * x) / sz;
			x_avg_y_avg = x_avg * y_avg;
			x_sq_avg = (x_sq_avg * n + x * x) / sz;
			x_avg_sq = x_avg * x_avg;
		} else {
			// Forget history before the window
			// to adopt to new pattern.
			sz = wsz;
			x_avg = x_avg - (win[ni].x - x) / sz;
			y_avg = y_avg - (win[ni].y - y) / sz;
			xy_avg = xy_avg - (win[ni].x * win[ni].y - y * x) / sz;
			x_avg_y_avg = x_avg * y_avg;
			x_sq_avg = x_sq_avg - (win[ni].x * win[ni].x - x * x)
					      / sz;
			x_avg_sq = x_avg * x_avg;
		}

		win[ni].x = x;
		win[ni].y = y;
		n++;

		if (x_sq_avg == x_avg_sq) {
			/* Trivial function. */
			a = 0;
			b = x_avg ? y_avg / x_avg : 1;
		} else {
			b = (xy_avg - x_avg_y_avg) / (x_sq_avg - x_avg_sq);
			a = (y_avg - b * x_avg) / MUL;
		}
#ifdef DEBUG
		std::cout << "-- x_avg=" << x_avg << " y_avg=" << y_avg
			  << " xy_avg=" << xy_avg
			  << " x_avg_y_avg=" << x_avg_y_avg
			  << " x_sq_avg=" << x_sq_avg
			  << " x_avg_sq=" << x_avg_sq << std::endl;
		std::cout << "-- win: " << win[0].x << "," << win[0].y
			  << " " << win[1].x << "," << win[1].y
			  << " " << win[2].x << "," << win[2].y
			  << " " << win[3].x << "," << win[3].y
			  << " " << win[4].x << "," << win[4].y << std::endl;
		std::cout << "-- a=" << a << " b=" << b << std::endl;
#endif
	}

	T
	slr_predict(long x)
	{
		return a + b * x;
	}

	void
	add_data(long x, long y)
	{
		std::cout << "-> x=" << x << " y=" << y << std::endl;
		slr_upd(x, y);
	}

	void
	predict(long x)
	{
		std::cout << "-> predict for " << x << " is "
			  << slr_predict(x) << std::endl;
	}
};

template<class T, const long wsz>
void
test()
{
	SLR<T, wsz> slr;

	slr.add_data(1, 3);
	slr.add_data(2, 5);
	slr.add_data(3, 11);
	slr.add_data(4, 2);
	slr.add_data(5, 7);
	slr.add_data(6, 0);
	slr.add_data(7, 1);
	slr.add_data(8, 100);
	slr.add_data(11, 9);
	slr.add_data(9, 2);
	slr.add_data(12, 6);
	slr.add_data(13, 8);

	slr.predict(15);
}

// The major thing this test verifies is that the calculations
// don't break when they're switched from working on partial
// history to working on full-size history.
template<class T, const long wsz>
void
test_verified()
{
	SLR<T, wsz> slr;

	slr.add_data(1, 1);
	slr.add_data(2, 1);
	slr.add_data(3, 1);
	slr.add_data(4, 1);
	slr.add_data(5, 1);
	slr.add_data(6, 1);
	slr.add_data(7, 1);
	slr.add_data(8, 1);
	slr.add_data(9, 1);
	slr.add_data(10, 1);
	slr.add_data(11, 1);
	slr.add_data(12, 1);
	slr.add_data(13, 1);

	slr.predict(15);
}

int
main(int argc, char *argv[])
{
	std::cout << "TEST for double" << std::endl;
	test<double, 5>();

	std::cout << "TEST for long" << std::endl;
	test<long, 5>();

	std::cout << "Verified test for long, the result should be '1'" << std::endl;
	test_verified<long, 8>();

	return 0;

	std::cout << std::endl;
	std::cout << "Input line format:" << std::endl;
	std::cout << std::endl;
	std::cout << "    curr_x curr_y prediction_x" << std::endl;
	std::cout << std::endl;
	std::cout << ", where prediction_x > curr_x is the time" << std::endl;
	std::cout << "which we need predict y for." << std::endl;
	std::cout << std::endl;
	std::cout << "> ";

	long x, y, pred_x;
	SLR<double, 5> slr;
	while (std::cin >> x >> y >> pred_x) {
		slr.slr_upd(x, y);
		std::cout << "(x=" << x << " y=" << y
			  << ") next y for x=" << pred_x
			  << " is " << slr.slr_predict(pred_x) << std::endl;
		std::cout << "\n> ";
	}

	return 0;
}
