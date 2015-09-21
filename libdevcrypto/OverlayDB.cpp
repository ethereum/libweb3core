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
std::map<u256, std::unordered_map<h256, uint > > OverlayDB::m_changes = {};

OverlayDB::~OverlayDB()
{
	if (m_db.use_count() == 1 && m_db.get())
		cnote << "Closing state DB";
}

class WriteBatchNoter: public ldb::WriteBatch::Handler
{
	virtual void Put(ldb::Slice const& _key, ldb::Slice const& _value) { cnote << "Put" << toHex(bytesConstRef(_key)) << "=>" << toHex(bytesConstRef(_value)); }
	virtual void Delete(ldb::Slice const& _key) { cnote << "Delete" << toHex(bytesConstRef(_key)); }
};

void OverlayDB::safeWrite(ldb::WriteBatch& _batch) const
{
	for (unsigned i = 0; i < 10; ++i)
	{
		ldb::Status o = m_db->Write(m_writeOptions, &_batch);
		if (o.ok())
			break;
		if (i == 9)
		{
			cwarn << "Fail writing to state database. Bombing out.";
			exit(-1);
		}
		cwarn << "Error writing to state database: " << o.ToString();
		WriteBatchNoter n;
		_batch.Iterate(&n);
		cwarn << "Sleeping for" << (i + 1) << "seconds, then retrying.";
		this_thread::sleep_for(chrono::seconds(i + 1));
	}
}

int OverlayDB::getRefCount(h256 const& _h) const
{
	bytes b = _h.asBytes();
	b.push_back(254); // for refcount

	// get refcount
	string refCount;
	if (m_db)
		m_db->Get(m_readOptions, bytesConstRef(&b), &refCount);

	if (refCount.empty())
		return 0;

	return stoi(refCount);
}

void OverlayDB::setRefCount(h256 const& _h, ldb::WriteBatch& _batch, int _refCount) const
{
	bytes b = _h.asBytes();
	b.push_back(254); // for refcount

	_batch.Put(bytesConstRef(&b), to_string(_refCount));
	m_changes[m_blockNumber][_h] = 2;
}

void OverlayDB::increaseRefCount(h256 const& _h,ldb::WriteBatch& _batch) const
{
	bytes b = _h.asBytes();
	b.push_back(254); // for refcount

	int refCountNumber = getRefCount(_h) + 1;

	_batch.Put(bytesConstRef(&b), to_string(refCountNumber));
	m_changes[m_blockNumber][_h] = 2;
}

void OverlayDB::decreaseRefCount(h256 const& _h,ldb::WriteBatch& _batch) const
{
	bytes b = _h.asBytes();
	b.push_back(254); // for refcount

	int refCountNumber = getRefCount(_h);
	refCountNumber = refCountNumber ? refCountNumber - 1 : refCountNumber;

	_batch.Put(bytesConstRef(&b), to_string(refCountNumber));
	m_changes[m_blockNumber][_h] = 1;
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
		ldb::WriteBatch batch;
//		cnote << "Committing nodes to disk DB:";

		// check if we need to revert changes in refCount (chain reorg)
		if (_blockNumber && m_changes.find(_blockNumber) != m_changes.end())
		{
			cout << "CHAIN REORG AT BLOCK: " << _blockNumber << endl;
			for (auto& i : m_changes[_blockNumber])
			{
				//undo changes
				if (i.second == 2) //it did get increased, decrease it now
				{
					decreaseRefCount(i.first, batch);
					cnote << "decreased refcount due to chain reorg";
				}
				else if (i.second == 1) // it did get decreases, now increase it
				{
					increaseRefCount(i.first, batch);
					cnote << "increased refcount due to chain reorg";
				}
			}
		}

#if DEV_GUARDED_DB
		DEV_READ_GUARDED(x_this)
#endif
		{
			for (auto const& i: m_main)
			{
				if (i.second.second)
				{
					batch.Put(ldb::Slice((char const*)i.first.data(), i.first.size), ldb::Slice(i.second.first.data(), i.second.first.size()));
					increaseRefCount(i.first, batch);

					h256 _h(i.first);
					u256 blockNumber = isInDeathRow(_h);
					if (blockNumber)
						m_deathrow[blockNumber].erase(_h);
				}
//				cnote << i.first << "#" << m_main[i.first].second;
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
		if (OverlayDB::m_blockNumber > PRUNING)
		{
			for (auto& _h : m_deathrow[OverlayDB::m_blockNumber - PRUNING])
				batch.Delete(ldb::Slice((char const*)_h.data(), 32));
			m_deathrow.erase(OverlayDB::m_blockNumber - PRUNING);
		}

		safeWrite(batch);

#if DEV_GUARDED_DB
		DEV_WRITE_GUARDED(x_this)
#endif
		{
			m_aux.clear();
			m_main.clear();
		}
	}
}

bytes OverlayDB::lookupAux(h256 const& _h) const
{
	bytes ret = MemoryDB::lookupAux(_h);
	if (!ret.empty() || !m_db)
		return ret;
	std::string v;
	bytes b = _h.asBytes();
	b.push_back(255);	// for aux
	m_db->Get(m_readOptions, bytesConstRef(&b), &v);
	if (v.empty())
		cwarn << "Aux not found: " << _h;

	return asBytes(v);
}

void OverlayDB::rollback()
{
#if DEV_GUARDED_DB
	WriteGuard l(x_this);
#endif
	m_main.clear();
}

std::string OverlayDB::lookup(h256 const& _h) const
{
	std::string ret = MemoryDB::lookup(_h);
	if (ret.empty() && m_db)
		m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);

	// pruning
	u256 blockNumber = isInDeathRow(_h);
	if (blockNumber)
		m_deathrow[blockNumber].erase(_h);

	ldb::WriteBatch batch;

	if (!getRefCount(_h))
		setRefCount(_h, batch);

	safeWrite(batch);

	return ret;
}

u256 OverlayDB::isInDeathRow(h256 const& _h) const
{
	for (auto& i : m_deathrow)
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
	if (m_db)
		m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);

	// pruning
	u256 blockNumber = isInDeathRow(_h);
	if (blockNumber)
		m_deathrow[blockNumber].erase(_h);

	ldb::WriteBatch batch;

	if (!getRefCount(_h))
		setRefCount(_h, batch);

	safeWrite(batch);

	return !ret.empty();
}

void OverlayDB::kill(h256 const& _h)
{
	if (!MemoryDB::kill(_h))
	{
		std::string ret;
		if (m_db)
			m_db->Get(m_readOptions, ldb::Slice((char const*)_h.data(), 32), &ret);
		// No point node ref decreasing for EmptyTrie since we never bother incrementing it in the first place for
		// empty storage tries.
		if (ret.empty() && _h != EmptyTrie)
			cnote << "Decreasing DB node ref count below zero with no DB node. Probably have a corrupt Trie." << _h;
		else
		{
			// decrease refcount
			bytes b = _h.asBytes();
			b.push_back(254); // for refcount

			int refCountNumber = getRefCount(_h);

			if (refCountNumber)
			{
				refCountNumber--;
				if (m_db)
					m_db->Put(m_writeOptions, bytesConstRef(&b), to_string(refCountNumber));
				m_changes[m_blockNumber][_h] = 1;
			}
			else
				cout << "REFCOUNT is ZERO, that means we kill a node which is not used by anyone!? Who is asking for that node?\n";

			if (!refCountNumber && !isInDeathRow(_h))
			{
				//cout << "added " << _h << " to deathrow in block: " << OverlayDB::m_blockNumber << endl;
				m_deathrow[OverlayDB::m_blockNumber].insert(_h);
			}
		}
	}
}

bool OverlayDB::deepkill(h256 const& _h)
{
	// kill in memoryDB
	kill(_h);

	//kill in overlayDB
	ldb::Status s = m_db->Delete(m_writeOptions, ldb::Slice((char const*)_h.data(), 32));
	if (s.ok())
		return true;
	else
		return false;
}

}

#endif // ETH_EMSCRIPTEN
