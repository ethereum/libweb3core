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
/** @file Common.cpp
 * @author Alex Leverington <nessence@gmail.com>
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include "Common.h"
#include <cstdint>
#include <chrono>
#include <thread>
#include <mutex>
#include <libscrypt/libscrypt.h>
#include <libdevcore/Guards.h>
#include <libdevcore/SHA3.h>
#include <libdevcore/RLP.h>
#if ETH_HAVE_SECP256K1
#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
#endif
#include "AES.h"
#include "CryptoPP.h"
#include "Exceptions.h"
using namespace std;
using namespace dev;
using namespace dev::crypto;

#ifdef ETH_HAVE_SECP256K1
std::unique_ptr<secp256k1_context, void(*)(secp256k1_context*)> s_secp256k1(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY), [](secp256k1_context* _c){ secp256k1_context_destroy(_c); });
#endif

static Secp256k1PP s_secp256k1pp;

static h256 const c_curveN("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

bool dev::SignatureStruct::isValid() const noexcept
{
	if (v > 1 ||
		r >= c_curveN ||
		s >= c_curveN ||
		s < h256(1) ||
		r < h256(1))
		return false;
	return true;
}

Public SignatureStruct::recover(h256 const& _hash) const
{
	return dev::recover((Signature)*this, _hash);
}

Address dev::ZeroAddress = Address();

Public dev::toPublic(Secret const& _secret)
{
#ifdef ETH_HAVE_SECP256K1
	secp256k1_pubkey pub;
	if (!secp256k1_ec_pubkey_create(s_secp256k1.get(), &pub, _secret.data()))
		return Public();
	size_t outlen = 0;
	byte out[65];
	if (!secp256k1_ec_pubkey_serialize(s_secp256k1.get(), out, &outlen, &pub, 0))
		return Public();
	return Public(out + 1, Public::ConstructFromPointer);
#else
	Public p;
	s_secp256k1pp.toPublic(_secret, p);
	return p;
#endif
}

Address dev::toAddress(Public const& _public)
{
	return right160(sha3(_public.ref()));
}

Address dev::toAddress(Secret const& _secret)
{
	Public p;
	s_secp256k1pp.toPublic(_secret, p);
	return toAddress(p);
}

Address dev::toAddress(Address const& _from, u256 const& _nonce)
{
	return right160(sha3(rlpList(_from, _nonce)));
}

void dev::encrypt(Public const& _k, bytesConstRef _plain, bytes& o_cipher)
{
	bytes io = _plain.toBytes();
	s_secp256k1pp.encrypt(_k, io);
	o_cipher = std::move(io);
}

bool dev::decrypt(Secret const& _k, bytesConstRef _cipher, bytes& o_plaintext)
{
	bytes io = _cipher.toBytes();
	s_secp256k1pp.decrypt(_k, io);
	if (io.empty())
		return false;
	o_plaintext = std::move(io);
	return true;
}

void dev::encryptECIES(Public const& _k, bytesConstRef _plain, bytes& o_cipher)
{
	bytes io = _plain.toBytes();
	s_secp256k1pp.encryptECIES(_k, io);
	o_cipher = std::move(io);
}

bool dev::decryptECIES(Secret const& _k, bytesConstRef _cipher, bytes& o_plaintext)
{
	bytes io = _cipher.toBytes();
	if (!s_secp256k1pp.decryptECIES(_k, io))
		return false;
	o_plaintext = std::move(io);
	return true;
}

void dev::encryptSym(Secret const& _k, bytesConstRef _plain, bytes& o_cipher)
{
	// TOOD: @alex @subtly do this properly.
	encrypt(KeyPair(_k).pub(), _plain, o_cipher);
}

bool dev::decryptSym(Secret const& _k, bytesConstRef _cipher, bytes& o_plain)
{
	// TODO: @alex @subtly do this properly.
	return decrypt(_k, _cipher, o_plain);
}

std::pair<bytes, h128> dev::encryptSymNoAuth(SecureFixedHash<16> const& _k, bytesConstRef _plain)
{
	h128 iv(Nonce::get().makeInsecure());
	return make_pair(encryptSymNoAuth(_k, iv, _plain), iv);
}

bytes dev::encryptAES128CTR(bytesConstRef _k, h128 const& _iv, bytesConstRef _plain)
{
	if (_k.size() != 16 && _k.size() != 24 && _k.size() != 32)
		return bytes();
	SecByteBlock key(_k.data(), _k.size());
	try
	{
		CTR_Mode<AES>::Encryption e;
		e.SetKeyWithIV(key, key.size(), _iv.data());
		bytes ret(_plain.size());
		e.ProcessData(ret.data(), _plain.data(), _plain.size());
		return ret;
	}
	catch (CryptoPP::Exception& _e)
	{
		cerr << _e.what() << endl;
		return bytes();
	}
}

bytesSec dev::decryptAES128CTR(bytesConstRef _k, h128 const& _iv, bytesConstRef _cipher)
{
	if (_k.size() != 16 && _k.size() != 24 && _k.size() != 32)
		return bytesSec();
	SecByteBlock key(_k.data(), _k.size());
	try
	{
		CTR_Mode<AES>::Decryption d;
		d.SetKeyWithIV(key, key.size(), _iv.data());
		bytesSec ret(_cipher.size());
		d.ProcessData(ret.writable().data(), _cipher.data(), _cipher.size());
		return ret;
	}
	catch (CryptoPP::Exception& _e)
	{
		cerr << _e.what() << endl;
		return bytesSec();
	}
}

static const Public c_zeroKey("3f17f1962b36e491b30a40b2405849e597ba5fb5");

Public dev::recover(Signature const& _sig, h256 const& _message)
{
	Public ret;
#ifdef ETH_HAVE_SECP256K1
	static_assert(sizeof(Signature) == 65, "sizeof(_sig) == 65");
	static_assert(sizeof(secp256k1_ecdsa_recoverable_signature) == 65, "sizeof(secp256k1_ecdsa_recoverable_signature) == 65");
	secp256k1_ecdsa_recoverable_signature sig;
	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(s_secp256k1.get(), &sig, _sig.data(), _sig.data()[64]))
		return Public();

	secp256k1_pubkey pub;
	if (!secp256k1_ecdsa_recover(s_secp256k1.get(), &pub, &sig, _message.data()))
		return Public();
	byte out[65];
	size_t outlen = 0;
	if (!secp256k1_ec_pubkey_serialize(s_secp256k1.get(), out, &outlen, &pub, 0))
		return Public();
	ret = Public(out + 1, Public::ConstructFromPointer);
#else
	ret = s_secp256k1pp.recover(_sig, _message.ref());
#endif
	if (ret == c_zeroKey)
		return Public();
	return ret;
}

Signature dev::sign(Secret const& _k, h256 const& _hash)
{
#ifdef ETH_HAVE_SECP256K1
	static_assert(sizeof(Signature) == 65, "sizeof(s) == 65");
	static_assert(sizeof(secp256k1_ecdsa_recoverable_signature) == 65, "sizeof(secp256k1_ecdsa_recoverable_signature) == 65");
	secp256k1_ecdsa_recoverable_signature sig;
	if (!secp256k1_ecdsa_sign_recoverable(s_secp256k1.get(), &sig, _hash.data(), _k.data(), nullptr, nullptr))
		return Signature();
	int v;
	Signature s;
	if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(s_secp256k1.get(), s.data(), &v, &sig))
		return Signature();
	s[64] = v;
	return s;
#else
	return s_secp256k1pp.sign(_k, _hash);
#endif
}

bool dev::verify(Public const& _p, Signature const& _s, h256 const& _hash)
{
	if (!_p)
		return false;
#ifdef ETH_HAVE_SECP256K1
	secp256k1_ecdsa_recoverable_signature sigr;
	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(s_secp256k1.get(), &sigr, _s.data(), _s.data()[64]))
		return false;
	secp256k1_ecdsa_signature sig;
	if (!secp256k1_ecdsa_recoverable_signature_convert(s_secp256k1.get(), &sig, &sigr))
		return false;
	secp256k1_pubkey pub;
	byte p[65] = { 4 };
	std::memcpy(p + 1, _p.data(), 64);
	if (!secp256k1_ec_pubkey_parse(s_secp256k1.get(), &pub, p, 65))
		return false;
	return secp256k1_ecdsa_verify(s_secp256k1.get(), &sig, _hash.data(), &pub) == 1;
#else
	return s_secp256k1pp.verify(_p, _s, _hash.ref(), true);
#endif
}

bytesSec dev::pbkdf2(string const& _pass, bytes const& _salt, unsigned _iterations, unsigned _dkLen)
{
	bytesSec ret(_dkLen);
	if (PKCS5_PBKDF2_HMAC<SHA256>().DeriveKey(
		ret.writable().data(),
		_dkLen,
		0,
		reinterpret_cast<byte const*>(_pass.data()),
		_pass.size(),
		_salt.data(),
		_salt.size(),
		_iterations
	) != _iterations)
		BOOST_THROW_EXCEPTION(CryptoException() << errinfo_comment("Key derivation failed."));
	return ret;
}

bytesSec dev::scrypt(std::string const& _pass, bytes const& _salt, uint64_t _n, uint32_t _r, uint32_t _p, unsigned _dkLen)
{
	bytesSec ret(_dkLen);
	if (libscrypt_scrypt(
		reinterpret_cast<uint8_t const*>(_pass.data()),
		_pass.size(),
		_salt.data(),
		_salt.size(),
		_n,
		_r,
		_p,
		ret.writable().data(),
		_dkLen
	) != 0)
		BOOST_THROW_EXCEPTION(CryptoException() << errinfo_comment("Key derivation failed."));
	return ret;
}

void KeyPair::populateFromSecret(Secret const& _sec)
{
	m_secret = _sec;
#ifdef ETH_HAVE_SECP256K1
	if (!secp256k1_ec_seckey_verify(s_secp256k1.get(), _sec.data()))
	{
		m_public.clear();
		m_address.clear();
		return;
	}
	m_public = toPublic(_sec);
#else
	if (!s_secp256k1pp.verifySecret(m_secret, m_public))
	{
		m_public.clear();
		m_address.clear();
		return;
	}
#endif
	m_address = toAddress(m_public);
}

KeyPair KeyPair::create()
{
	for (int i = 0; i < 100; ++i)
	{
		KeyPair ret(Secret::random());
		if (ret.address())
			return ret;
	}
	return KeyPair();
}

KeyPair KeyPair::fromEncryptedSeed(bytesConstRef _seed, std::string const& _password)
{
	return KeyPair(Secret(sha3(aesDecrypt(_seed, _password))));
}

h256 crypto::kdf(Secret const& _priv, h256 const& _hash)
{
	// H(H(r||k)^h)
	h256 s;
	sha3mac(Secret::random().ref(), _priv.ref(), s.ref());
	s ^= _hash;
	sha3(s.ref(), s.ref());
	
	if (!s || !_hash || !_priv)
		BOOST_THROW_EXCEPTION(InvalidState());
	return s;
}

Secret Nonce::next()
{
	Guard l(x_value);
	if (!m_value)
	{
		m_value = Secret::random();
		if (!m_value)
			BOOST_THROW_EXCEPTION(InvalidState());
	}
	m_value = sha3Secure(m_value.ref());
	return sha3(~m_value);
}
