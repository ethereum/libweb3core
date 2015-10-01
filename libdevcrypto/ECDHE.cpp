/*
 This file is part of cpp-ethereum.
 
 cpp-ethereum is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 cpp-ethereum is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
 */
/** @file ECDHE.cpp
 * @author Alex Leverington <nessence@gmail.com>
 * @date 2014
 */

#include "ECDHE.h"
#include <libdevcore/SHA3.h>

#include "CryptoPP.h"
#if ETH_HAVE_SECP256K1
#include <secp256k1/include/ext.h>
#endif

using namespace std;
using namespace dev;
using namespace dev::crypto;

#if ETH_HAVE_SECP256K1
extern std::unique_ptr<secp256k1_context, void(*)(secp256k1_context*)> s_secp256k1;
#else
static Secp256k1PP s_secp256k1;
#endif

void dev::crypto::ecdh::agree(Secret const& _s, Public const& _p, Secret& o_s)
{
#ifdef ETH_HAVE_SECP256K1
	byte p[65] = { 4 };
	std::memcpy(p + 1, _p.data(), 64);
	secp256k1_pubkey pub;
	if (!secp256k1_ec_pubkey_parse(s_secp256k1.get(), &pub, p, 65))
		return;

	if (!secp256k1_ecdh_raw(s_secp256k1.get(), o_s.writable().data(), &pub, _s.data()))
		return;
#else
	s_secp256k1.agree(_s, _p, o_s);
#endif
}

void ECDHE::agree(Public const& _remote, Secret& o_sharedSecret) const
{
	if (m_remoteEphemeral)
		// agreement can only occur once
		BOOST_THROW_EXCEPTION(InvalidState());
	
	m_remoteEphemeral = _remote;
	dev::crypto::ecdh::agree(m_ephemeral.sec(), m_remoteEphemeral, o_sharedSecret);
}
