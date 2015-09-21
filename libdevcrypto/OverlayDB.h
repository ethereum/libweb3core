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
/** @file OverlayDB.h
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#pragma once

#include <memory>
#include <libdevcore/db.h>
#include <libdevcore/Common.h>
#include <libdevcore/Log.h>
#include <libdevcore/MemoryDB.h>

#define PRUNING 100

namespace dev
{

class OverlayDB: public MemoryDB
{
public:
	OverlayDB(ldb::DB* _db = nullptr): m_db(_db) {}
	~OverlayDB();

	ldb::DB* db() const { return m_db.get(); }

	void commit(u256 _blockNumber);
	void rollback();

	std::string lookup(h256 const& _h) const;
	bool exists(h256 const& _h) const;
	void kill(h256 const& _h);
	bool deepkill(h256 const& _h);

	bytes lookupAux(h256 const& _h) const;

private:
	using MemoryDB::clear;

	std::shared_ptr<ldb::DB> m_db;

	ldb::ReadOptions m_readOptions;
	ldb::WriteOptions m_writeOptions;

#ifdef PRUNING
	u256 isInDeathRow(h256 const& _h) const;
	int getRefCount(h256 const& _h) const;
	void increaseRefCount(h256 const& _h,ldb::WriteBatch& _batch) const;
	void decreaseRefCount(h256 const& _h,ldb::WriteBatch& _batch) const;
	void setRefCount(h256 const& _h, ldb::WriteBatch& _batch, int _refCount = 1) const;

	void safeWrite(ldb::WriteBatch& _batch) const;

	static std::map<u256, std::set<h256> > m_deathrow;
	static std::map<u256, std::unordered_map<h256, uint > > m_changes;
	static u256 m_blockNumber; //updated in commit()
#endif

};

}
