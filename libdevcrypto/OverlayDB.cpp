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
/** @file OverlayDB.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */
#if !defined(ETH_EMSCRIPTEN)

#include <thread>
#include <libdevcore/db.h>
#include <libdevcore/Common.h>
#include "OverlayDB.h"
using namespace std;
using namespace dev;

namespace dev
{

h256 const EmptyTrie = sha3(rlp(""));

u256 OverlayDB::m_blockNumber = 0;
std::map<u256, std::set<h256> > OverlayDB::m_deathrow = {};
std::map<u256, std::unordered_map<h256, int > > OverlayDB::m_changes = {};

class WriteBatchNoter: public ldb::WriteBatch::Handler
{
	virtual void Put(ldb::Slice const& _key, ldb::Slice const& _value) { cnote << "Put" << toHex(bytesConstRef(_key)) << "=>" << toHex(bytesConstRef(_value)); }
	virtual void Delete(ldb::Slice const& _key) { cnote << "Delete" << toHex(bytesConstRef(_key)); }
};

OverlayDB::~OverlayDB()
{
	if (m_db.use_count() == 1 && m_db.get())
		cnote << "Closing state DB";
}

void OverlayDB::commit(u256 _blockNumber)
{
#ifdef PRUNING
	OverlayDB::m_blockNumber = _blockNumber;
#else
	void(_blockNumber);
#endif

	if (m_db)
	{
		ldb::WriteBatch batchR;

		cout << "blocknumber: " << m_blockNumber << endl;

		// check if we need to revert changes in refCount (chain reorg)
		u256 tmp_blockNumber = _blockNumber;
		while (_blockNumber && m_changes.find(tmp_blockNumber) != m_changes.end())
		{
			cout << "CHAIN REORG AT BLOCK: " << _blockNumber << endl;
			cout << "reverting changes of block " << tmp_blockNumber << endl;
			for (auto& i : m_changes[_blockNumber])
			{
				increaseRefCount(i.first, batchR, -i.second, true);
			}
			m_deathrow[tmp_blockNumber].clear();
			m_changes[tmp_blockNumber].clear();
			tmp_blockNumber++;
		}

		safeWrite(batchR);
		ldb::WriteBatch batch;

#if DEV_GUARDED_DB
		DEV_READ_GUARDED(x_this)
#endif
		{
			for (auto const& i: m_main)
			{
				h256 _h(i.first);
				if (i.second.second > 0)
				{
					batch.Put(ldb::Slice((char const*)i.first.data(), i.first.size), ldb::Slice(i.second.first.data(), i.second.first.size()));
					increaseRefCount(i.first, batch, i.second.second);

					u256 blockNumber = isInDeathRow(_h);
					if (blockNumber != 0)
						m_deathrow[blockNumber].erase(_h);
				}
				else if(i.second.second < 0)
				{
					int newRefCount = increaseRefCount(_h, batch, i.second.second);
					if (newRefCount <= 0)
						m_deathrow[OverlayDB::m_blockNumber].insert(_h);
					if (newRefCount < 0)
					{
						cwarn << "REFCOUNT SMALLER THAN ZERO, that means we re-kill a node which is not used by anyone!? Who is asking for that node? Probably a critical trie issue";
						cwarn << "hash: " << i.first ;
						cwarn << "previous refcount: " << getRefCount(i.first) << " now add: " << i.second.second;
						cwarn << "so the new refcount is: " << newRefCount;
						//cin.get();
					}

				}
				else if (_blockNumber == 0)
				{
					batch.Put(ldb::Slice((char const*)i.first.data(), i.first.size), ldb::Slice(i.second.first.data(), i.second.first.size()));
					increaseRefCount(i.first, batch, i.second.second);
				}
			}
			for (auto const& i: m_aux)
				if (i.second.second)
				{
					bytes b = i.first.asBytes();
					b.push_back(255);	// for aux

					batch.Put(bytesConstRef(&b), bytesConstRef(&i.second.first));
				}
		}

		// pruning
#if DEV_GUARDED_DB
		DEV_WRITE_GUARDED(x_this)
#endif
		{
			if (OverlayDB::m_blockNumber > PRUNING)
			{
				for (auto& _h : m_deathrow[OverlayDB::m_blockNumber - PRUNING])
				{
					batch.Delete(ldb::Slice((char const*)_h.data(), 32)); //delete refcount too

					bytes b = _h.asBytes();
					b.push_back(255);	// for aux
					batch.Delete(bytesConstRef(&b));

					bytes bRefCount = _h.asBytes();
					bRefCount.push_back(254);	// for refcount
					batch.Delete(bytesConstRef(&bRefCount));
				}
				m_deathrow.erase(OverlayDB::m_blockNumber - PRUNING);
				m_changes.erase(OverlayDB::m_blockNumber - PRUNING);
			}
			safeWrite(batch);
		}
		{
			m_aux.clear();
			m_main.clear();
		}
	}
	else
		cwarn << "m_db not accessible in commit!!";
}

bytes OverlayDB::lookupAux(h256 const& _h) const
{
	bytes ret = MemoryDB::lookupAux(_h);
	if (!ret.empty() || !m_db)
		return ret;
	std::string v;
	bytes b = _h.asBytes();
	b.push_back(255);	// for aux

	if (!m_db)
		cwarn << "m_db not accessible in kill!!";

	m_db->Get(m_readOptions, bytesConstRef(&b), &v);
	if (v.empty())
		cwarn << "Aux not found: " << _h;

	return asBytes(v);
}

void OverlayDB::rollback()
{
	cout << "ROLLBACK in OVERLAYDB called\n";
	cout << "at blocknumber: " << m_blockNumber << endl;
#if DEV_GUARDED_DB
	DEV_WRITE_GUARDED(x_this)
#endif
	{
		m_main.clear();
	}
}

std::string OverlayDB::lookup(h256 const& _h) const
{
	std::string ret;
#if DEV_GUARDED_DB
	DEV_READ_GUARDED(x_this)
#endif
	{
		ret = MemoryDB::lookup(_h);

		if (ret.empty() && m_db)
			m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);
		else
			return ret;
	}

	if (ret.empty())
		return ret;


	ldb::WriteBatch batch;

	if (!getRefCount(_h) && _h != EmptyTrie)
	{
		cwarn << "lookup request for: " << _h << " with refcount 0\n This is probably a critical trie issue or";
		cwarn << "might be just reverting some blocks";

#if DEV_GUARDED_DB
		DEV_WRITE_GUARDED(x_this)
#endif
		{
			increaseRefCount(_h, batch);
			safeWrite(batch);

			// pruning
			u256 blockNumber = isInDeathRow(_h);
			if (blockNumber)
				m_deathrow[blockNumber].erase(_h);
		}
	}
	return ret;
}

u256 OverlayDB::isInDeathRow(h256 const& _h) const
{
	for (auto const& i : OverlayDB::m_deathrow)
	{
		if (i.second.find(_h) != i.second.end())
			return i.first;
	}
	return 0;
}

bool OverlayDB::exists(h256 const& _h) const
{

	if (MemoryDB::exists(_h))
		return true;

	std::string ret;

#if DEV_GUARDED_DB
	DEV_READ_GUARDED(x_this)
#endif
	{
		if (m_db)
			m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);
	}

	if (ret.empty())
		return false;

	ldb::WriteBatch batch;

	if (!getRefCount(_h) && _h != EmptyTrie)
	{
		cwarn << "exists request for: " << _h << " with refcount 0";
#if DEV_GUARDED_DB
		DEV_WRITE_GUARDED(x_this);
#endif
		{
			//setRefCount(_h, batch);
			//safeWrite(batch);

			// pruning
			u256 blockNumber = isInDeathRow(_h);
			if (blockNumber)
				m_deathrow[blockNumber].erase(_h);
		}
	}

	return !ret.empty();
}

void OverlayDB::insert(h256 const& _h, bytesConstRef _v)
{
	MemoryDB::insert(_h, _v);
}


void OverlayDB::kill(h256 const& _h)
{
	if (!MemoryDB::kill(_h) && _h != EmptyTrie)
	{
		cwarn << "should never arrive here!";
//		std::string ret;
//#if DEV_GUARDED_DB
//		DEV_READ_GUARDED(x_this)
//#endif
//		{
//			if (m_db)
//				m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);
//			else
//				cwarn << "m_db not accessible in kill!!";
//		}


//		// No point node ref decreasing for EmptyTrie since we never bother incrementing it in the first place for
//		// empty storage tries.
//		if (ret.empty() && _h != EmptyTrie)
//			cnote << "Decreasing DB node ref count below zero with no DB node. Probably have a corrupt Trie." << _h;
//		else
//		{
//#if DEV_GUARDED_DB
//			DEV_WRITE_GUARDED(x_this);
//#endif
//			{
//				// decrease refcount
//				ldb::WriteBatch batch;

//				if (!decreaseRefCount(_h, batch) && !isInDeathRow(_h))
//				{
//					//cout << "added " << _h << " to deathrow in block: " << OverlayDB::m_blockNumber << endl;
//					m_deathrow[OverlayDB::m_blockNumber].insert(_h);
//				}
//				safeWrite(batch);
//			}
//		}
	}
}

void OverlayDB::safeWrite(ldb::WriteBatch& _batch) const
{
#if DEV_GUARDED_DB
	DEV_WRITE_GUARDED(x_this);
#endif
	{
		for (unsigned i = 0; i < 10; ++i)
		{

			ldb::Status o;
			if (m_db)
				o = m_db->Write(m_writeOptions, &_batch);
			else if (m_blockNumber > PRUNING)
			{
				cwarn << "m_db not accessible in safewrite!!";
			}

			if (m_db && o.ok())
				break;
			if (i == 3)
				break;
			if (i == 9)
			{
				cwarn << "Fail writing to state database. Bombing out.";
				exit(-1);
			}
			cwarn << "Error writing to state database: " << o.ToString();
			WriteBatchNoter n;
			_batch.Iterate(&n);
			cwarn << "Sleeping for" << (i + 1) << "seconds, then retry writing.";
			this_thread::sleep_for(chrono::seconds(i + 1));
		}
	}
}

int OverlayDB::getRefCount(h256 const& _h) const
{
	string refCount;
#if DEV_GUARDED_DB
	DEV_READ_GUARDED(x_this);
#endif
	{
		bytes b = _h.asBytes();
		b.push_back(254); // for refcount

		// get refcount
		if (m_db)
			m_db->Get(m_readOptions, bytesConstRef(&b), &refCount);
		else
			cwarn << "m_db not accessible in getRefCount!!";
	}

	if (refCount.empty())
		return 0;

	return stoi(refCount);
}

int OverlayDB::increaseRefCount(h256 const& _h,ldb::WriteBatch& _batch, int _addedRefCount, bool _revert) const
{
	bytes b = _h.asBytes();
	b.push_back(254); // for refcount

	cout << "increaseRefcount for: " << _h << " by " << _addedRefCount << " with revert: " << _revert << endl;
	cout << "before: " << getRefCount(_h);

	int refCountNumber = getRefCount(_h) + _addedRefCount;
	cout << " after: " << refCountNumber << endl;
#if DEV_GUARDED_DB
	DEV_WRITE_GUARDED(x_this);
#endif
	{
		_batch.Put(bytesConstRef(&b), to_string(refCountNumber));
		if (!_revert)
			m_changes[m_blockNumber][_h] += _addedRefCount;
	}
	return refCountNumber;
}
}

#endif // ETH_EMSCRIPTEN
