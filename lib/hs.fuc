// Copyright (C) 2020  The Mirage Authors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Prepares to enter the Heavy Secure Mode by clearing all crypto registers.
define(`PREPARE_HEAVY_SECURE_MODE_ENTRY', dnl
cxor $c0 $c0
cmov $c1 $c0
cmov $c2 $c0
cmov $c3 $c0
cmov $c4 $c0
cmov $c5 $c0
)

// Prepares to leave the Heavy Secure Mode by clearing the MAC of the running
// code and blanking all the crypto registers.
define(`PREPARE_HEAVY_SECURE_MODE_EXIT', dnl
csigclr
cxor $c0 $c0
cxor $c1 $c1
cxor $c2 $c2
cxor $c3 $c3
cxor $c4 $c4
cxor $c5 $c5
cxor $c6 $c6
cxor $c7 $c7
)
