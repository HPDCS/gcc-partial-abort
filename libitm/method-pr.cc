/* Copyright (C) 2012-2018 Free Software Foundation, Inc.
   Contributed by Torvald Riegel <triegel@redhat.com>.

   This file is part of the GNU Transactional Memory Library (libitm).

   Libitm is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Libitm is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#include "libitm_i.h"
#include <stdio.h>
#include <sys/time.h>


/*******************************************************************/
/*					INIZIO aggiunta					  */
/*******************************************************************/

/*  Define per le due funzioni */
#define offsetof_ext_jmpbuf_rax		0
#define offsetof_ext_jmpbuf_rdx		8
#define offsetof_ext_jmpbuf_rcx		16
#define offsetof_ext_jmpbuf_rbx		24
#define offsetof_ext_jmpbuf_rsp		32
#define offsetof_ext_jmpbuf_rbp		40
#define offsetof_ext_jmpbuf_rsi		48
#define offsetof_ext_jmpbuf_rdi		56
#define offsetof_ext_jmpbuf_r8		64
#define offsetof_ext_jmpbuf_r9		72
#define offsetof_ext_jmpbuf_r10		80
#define offsetof_ext_jmpbuf_r11		88
#define offsetof_ext_jmpbuf_r12		96
#define offsetof_ext_jmpbuf_r13		104
#define offsetof_ext_jmpbuf_r14		112
#define offsetof_ext_jmpbuf_r15		120
#define offsetof_ext_jmpbuf_rip		128
#define offsetof_ext_jmpbuf_flags	136
#define offsetof_ext_jmpbuf_fpu		144

#define old_flags	0
#define old_r11		8
#define old_rax		16
#define ret_addr	24
#define old_rdi		32

/* Needed to convert the defines into strings that can be concatenated */
#define DCHPC_STRINGIFY(X) #X
#define DCHPC_STR(X) DCHPC_STRINGIFY(X)

/* Qui definiamo le funzioni che andremo a usare */
/* Per mantenere il codice pulito, si usa la concatenazione delle stringhe e dei valori definiti con define */

// Vedere se funziona
__attribute__ ((noinline)) 
long long _ext_setjmp(ext_jmpbuf *jb) {
	asm volatile (\
		"pushq %rax													\n"\
		"pushq %r11													\n"\
																	   \
		"lahf														\n"\
		"seto %al													\n"\
		"pushq %rax													\n"\
																	   \
		"movq %rdi, %rax											\n"\
		"movq " DCHPC_STR(old_rax) "(%rsp), %r11					\n"\
																	   \
		"movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rax) "(%rax)	\n"\
		"movq %rdx, " DCHPC_STR(offsetof_ext_jmpbuf_rdx) "(%rax)	\n"\
		"movq %rcx, " DCHPC_STR(offsetof_ext_jmpbuf_rcx) "(%rax)	\n"\
		"movq %rbx, " DCHPC_STR(offsetof_ext_jmpbuf_rbx) "(%rax)	\n"\
		"movq %rsp, " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax)	\n"\
		"addq $16,  " DCHPC_STR(offsetof_ext_jmpbuf_rsp) "(%rax)	\n"\
		"movq %rbp, " DCHPC_STR(offsetof_ext_jmpbuf_rbp) "(%rax)	\n"\
		"movq %rsi, " DCHPC_STR(offsetof_ext_jmpbuf_rsi) "(%rax)	\n"\
																	   \
		"movq " DCHPC_STR(old_rdi) "(%rsp), %r11					\n"\
		"movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rdi) "(%rax)	\n"\
		"movq %r8, " DCHPC_STR(offsetof_ext_jmpbuf_r8) "(%rax)		\n"\
		"movq %r9, " DCHPC_STR(offsetof_ext_jmpbuf_r9) "(%rax)		\n"\
		"movq %r10, " DCHPC_STR(offsetof_ext_jmpbuf_r10) "(%rax)	\n"\
		"movq " DCHPC_STR(old_r11) "(%rsp), %r11					\n"\
		"movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_r11) "(%rax)	\n"\
		"movq %r12, " DCHPC_STR(offsetof_ext_jmpbuf_r12) "(%rax)	\n"\
		"movq %r13, " DCHPC_STR(offsetof_ext_jmpbuf_r13) "(%rax)	\n"\
		"movq %r14, " DCHPC_STR(offsetof_ext_jmpbuf_r14) "(%rax)	\n"\
		"movq %r15, " DCHPC_STR(offsetof_ext_jmpbuf_r15) "(%rax)	\n"\
																	   \
		"movq " DCHPC_STR(old_flags) "(%rsp), %rdx					\n"\
		"movq %rdx, " DCHPC_STR(offsetof_ext_jmpbuf_flags) "(%rax)	\n"\
																	   \
		"movq " DCHPC_STR(ret_addr) "(%rsp), %r11					\n"\
		"movq %r11, " DCHPC_STR(offsetof_ext_jmpbuf_rip) "(%rax)	\n"\
																	   \
		"fsave " DCHPC_STR(offsetof_ext_jmpbuf_fpu) "(%rax)			\n"\
		/* the line above and below this comment are mutually exclusive and architecture dependent*/\
		/*"fxsave " DCHPC_STR(offsetof_ext_jmpbuf_fpu) "(%rax)		\n"*/\
																	   \
		"addq $24, %rsp												\n"\
		"xorq %rax, %rax											\n"\
		"ret														"\
	);
	/* Any code here is unreachable */
	return 0;
}

#define ext_setjmp(jb_ptr) 	({\
				int _set_ret;\
				__asm__ __volatile__ ("pushq %rdi"); \
				_set_ret = _ext_setjmp(jb_ptr); \
				__asm__ __volatile__ ("add $8, %rsp"); \
				_set_ret;\
})

#pragma GCC poison _ext_setjmp


/* undefine */
#undef old_flags
#undef old_r11
#undef old_rax
#undef ret_addr
#undef old_rdi

#undef offsetof_ext_jmpbuf_rax	
#undef offsetof_ext_jmpbuf_rdx	
#undef offsetof_ext_jmpbuf_rcx	
#undef offsetof_ext_jmpbuf_rbx	
#undef offsetof_ext_jmpbuf_rsp	
#undef offsetof_ext_jmpbuf_rbp	
#undef offsetof_ext_jmpbuf_rsi	
#undef offsetof_ext_jmpbuf_rdi	
#undef offsetof_ext_jmpbuf_r8	
#undef offsetof_ext_jmpbuf_r9	
#undef offsetof_ext_jmpbuf_r10	
#undef offsetof_ext_jmpbuf_r11	
#undef offsetof_ext_jmpbuf_r12	
#undef offsetof_ext_jmpbuf_r13	
#undef offsetof_ext_jmpbuf_r14	
#undef offsetof_ext_jmpbuf_r15	
#undef offsetof_ext_jmpbuf_rip	
#undef offsetof_ext_jmpbuf_flags
#undef offsetof_ext_jmpbuf_fpu	

#undef DCHPC_STR
#undef DCHPC_STRINGIFY

/*******************************************************************/
/*					FINE dell'aggiunta					*/
/*******************************************************************/

using namespace GTM;

namespace {

// This group consists of all TM methods that synchronize via multiple locks
// (or ownership records).
struct ml_mg : public method_group{

  static const gtm_word LOCK_BIT = (~(gtm_word)0 >> 1) + 1; // 10000000...
  static const gtm_word INCARNATION_BITS = 3;
  static const gtm_word INCARNATION_MASK = 7;
  // Maximum time is all bits except the lock bit, the overflow reserve bit,
  // and the incarnation bits.
  static const gtm_word TIME_MAX = (~(gtm_word)0 >> (2 + INCARNATION_BITS));
  // The overflow reserve bit is the MSB of the timestamp part of an orec,
  // so we can have TIME_MAX+1 pending timestamp increases before we overflow.
  static const gtm_word OVERFLOW_RESERVE = TIME_MAX + 1;

  static bool is_locked(gtm_word o) { return o & LOCK_BIT; }
  
  static gtm_word set_locked(gtm_thread *tx) {
    return ((uintptr_t)tx >> 1) | LOCK_BIT;
  }
  
  static gtm_word get_time(gtm_word o) { return o >> INCARNATION_BITS; } // Returns a time that includes the lock bit, which is required by both validate() and is_more_recent_or_locked().
  static gtm_word set_time(gtm_word time) { return time << INCARNATION_BITS; }

  static bool is_more_recent_or_locked(gtm_word o, gtm_word than_time) {
    // LOCK_BIT is the MostSignificantBit; thus, if o is locked, it is larger than TIME_MAX.
    return get_time(o) > than_time;
  }

  static bool has_incarnation_left(gtm_word o) {
    return (o & INCARNATION_MASK) < INCARNATION_MASK;
  }

  static gtm_word inc_incarnation(gtm_word o) { return o + 1; }

  // The shared time base.
  atomic<gtm_word> time __attribute__((aligned(HW_CACHELINE_SIZE)));

  // The array of ownership records.
  atomic<gtm_word>* orecs __attribute__((aligned(HW_CACHELINE_SIZE)));
  char tailpadding[HW_CACHELINE_SIZE - sizeof(atomic<gtm_word>*)];

  // Location-to-orec mapping.  Stripes of 32B mapped to 2^16 orecs using
  // multiplicative hashing.  See Section 5.2.2 of Torvald Riegel's PhD thesis
  // for the background on this choice of hash function and parameters:
  // http://nbn-resolving.de/urn:nbn:de:bsz:14-qucosa-115596
  // We pick the Mult32 hash because it works well with fewer orecs (i.e.,
  // less space overhead and just 32b multiplication).
  // We may want to check and potentially change these settings once we get
  // better or just more benchmarks.
  static const gtm_word L2O_ORECS_BITS = 16;
  static const gtm_word L2O_ORECS = 1 << L2O_ORECS_BITS; // cioè 2^16 cioè 65536
  // An iterator over the orecs covering the region [addr,addr+len].
  struct orec_iterator{
    static const gtm_word L2O_SHIFT = 5;
    static const uint32_t L2O_MULT32 = 81007;
    uint32_t mult;
    size_t orec;
    size_t orec_end;
    orec_iterator (const void* addr, size_t len){
      uint32_t a = (uintptr_t) addr >> L2O_SHIFT;
      uint32_t ae = ((uintptr_t) addr + len + (1 << L2O_SHIFT) - 1) >> L2O_SHIFT;
      mult = a * L2O_MULT32;
      orec = mult >> (32 - L2O_ORECS_BITS);
      // We can't really avoid this second multiplication unless we use a
      // branch instead or know more about the alignment of addr.  (We often
      // know len at compile time because of instantiations of functions
      // such as _ITM_RU* for accesses of specific lengths.
      orec_end = (ae * L2O_MULT32) >> (32 - L2O_ORECS_BITS);
    }
    size_t get() { return orec; }
    void advance(){
      // We cannot simply increment orec because L2O_MULT32 is larger than
      // 1 << (32 - L2O_ORECS_BITS), and thus an increase of the stripe (i.e.,
      // addr >> L2O_SHIFT) could increase the resulting orec index by more
      // than one; with the current parameters, we would roughly acquire a
      // fourth more orecs than necessary for regions covering more than orec.
      // Keeping mult around as extra state shouldn't matter much.
      mult += L2O_MULT32;
      orec = mult >> (32 - L2O_ORECS_BITS);
    }
    bool reached_end() { return orec == orec_end; }
  };

  virtual void init(){
    // We assume that an atomic<gtm_word> is backed by just a gtm_word, so
    // starting with zeroed memory is fine.
    orecs = (atomic<gtm_word>*) xcalloc(
        sizeof(atomic<gtm_word>) * L2O_ORECS, true);
    // This store is only executed while holding the serial lock, so relaxed
    // memory order is sufficient here.
    time.store(0, memory_order_relaxed);
  }

  virtual void fini(){
    free(orecs);
  }

  // We only re-initialize when our time base overflows.  Thus, only reset
  // the time base and the orecs but do not re-allocate the orec array.
  virtual void reinit(){
    // This store is only executed while holding the serial lock, so relaxed
    // memory order is sufficient here.  Same holds for the memset.
    time.store(0, memory_order_relaxed);
    // The memset below isn't strictly kosher because it bypasses
    // the non-trivial assignment operator defined by std::atomic.  Using
    // a local void* is enough to prevent GCC from warning for this.
    void *p = orecs;
    memset(p, 0, sizeof(atomic<gtm_word>) * L2O_ORECS);
  }
};

static ml_mg o_ml_mg;











// The multiple lock, write-through TM method.
// Maps each memory location to one of the orecs in the orec array, and then
// acquires the associated orec eagerly before writing through.
// Writes require undo-logging because we are dealing with several locks/orecs
// and need to resolve deadlocks if necessary by aborting one of the
// transactions.
// Reads do time-based validation with snapshot time extensions. Incarnation
// numbers are used to decrease contention on the time base (with those,
// aborted transactions do not need to acquire a new version number for the
// data that has been previously written in the transaction and needs to be
// rolled back).
// gtm_thread::shared_state is used to store a transaction's current
// snapshot time (or commit time). The serial lock uses ~0 for inactive
// transactions and 0 for active ones. Thus, we always have a meaningful
// timestamp in shared_state that can be used to implement quiescence-based
// privatization safety.
class ml_wt_pr_dispatch : public abi_dispatch {
protected:
  static void pre_write(gtm_thread *tx, const void *addr, size_t len) {
    
    gtm_word snapshot = tx->shared_state.load(memory_order_relaxed);
    gtm_word locked_by_tx = ml_mg::set_locked(tx);

    // Lock all orecs that cover the region.
    ml_mg::orec_iterator oi(addr, len);
    do{
        // Load the orec. Relaxed memory order is sufficient here because
        // either we have acquired the orec or we will try to acquire it with
        // a CAS with stronger memory order.
        gtm_word o = o_ml_mg.orecs[oi.get()].load(memory_order_relaxed);

        // Check whether we have acquired the orec already.
        if (likely (locked_by_tx != o)) {
			      // tx did not acquired this specific orec
            // If not, acquire.  Make sure that our snapshot time is larger or
            // equal than the orec's version to avoid masking invalidations of
            // our snapshot with our own writes.
            if (unlikely ((ml_mg::is_locked(o)))){
              tx->restart(RESTART_LOCKED_WRITE);
			      }

            if (unlikely (ml_mg::get_time(o) > snapshot)) {
                // We only need to extend the snapshot if we have indeed read
                // from this orec before.  Given that we are an update
                // transaction, we will have to extend anyway during commit.
                // ??? Scan the read log instead, aborting if we have read
                // from data covered by this orec before?
                snapshot = extend(tx);
                //try_to_extend_with_partial_rollback(tx);
            }

            // We need acquire memory order here to synchronize with other
            // (ownership) releases of the orec.  We do not need acq_rel order
            // because whenever another thread reads from this CAS'
            // modification, then it will abort anyway and does not rely on
            // any further happens-before relation to be established.
            
            if (unlikely (!o_ml_mg.orecs[oi.get()].compare_exchange_strong(
                          o, locked_by_tx, memory_order_acquire)))
              tx->restart(RESTART_LOCKED_WRITE);

            // We use an explicit fence here to avoid having to use release
            // memory order for all subsequent data stores.  This fence will
            // synchronize with loads of the data with acquire memory order.
            // See post_load() for why this is necessary.
            // Adding require memory order to the prior CAS is not sufficient,
            // at least according to the Batty et al. formalization of the
            // memory model.
            atomic_thread_fence(memory_order_release);

            // We log the previous value here to be able to use incarnation
            // numbers when we have to roll back.
            // ??? Reserve capacity early to avoid capacity checks here?
            
            gtm_rwlog_entry *e = tx->writelog.push();
            e->orec = o_ml_mg.orecs + oi.get();
            e->value = o;
            
        }
        oi.advance();
    }while(!oi.reached_end());

    // Do undo logging.  We do not know which region prior writes logged
    // (even if orecs have been acquired), so just log everything.
    tx->undolog.log(addr, len);
  }

  static void pre_write(const void *addr, size_t len) {
    gtm_thread *tx = gtm_thr();
    pre_write(tx, addr, len);
  }


  // Returns true iff all the orecs in our read log still have the same time
  // or have been locked by the transaction itself.
  static bool validate(gtm_thread *tx) {
    gtm_word locked_by_tx = ml_mg::set_locked(tx);
    // ??? This might get called from pre_load() via extend().  In that case,
    // we don't really need to check the new entries that pre_load() is
    // adding.  Stop earlier?
    for (gtm_rwlog_entry *i = tx->readlog.begin(), *ie = tx->readlog.end(); i != ie; i++) {
      // Relaxed memory order is sufficient here because we do not need to
      // establish any new synchronizes-with relationships.  We only need
      // to read a value that is as least as current as enforced by the
      // callers: extend() loads global time with acquire, and trycommit()
      // increments global time with acquire.  Therefore, we will see the
      // most recent orec updates before the global time that we load.
        gtm_word o = i->orec->load(memory_order_relaxed);
        // We compare only the time stamp and the lock bit here.  We know that
        // we have read only committed data before, so we can ignore
        // intermediate yet rolled-back updates presented by the incarnation
        // number bits.
        if (ml_mg::get_time(o) != ml_mg::get_time(i->value) && o != locked_by_tx) // se l'orec è stato aggiornato, e non da me, ritorna false
          return false;
    }
    return true;
  }


  // Tries to extend the snapshot to a more recent time.  Returns the new
  // snapshot time and updates TX->SHARED_STATE. If the snapshot cannot be
  // extended to the current global time, TX is restarted.
  static gtm_word extend(gtm_thread *tx) {
    // We read global time here, even if this isn't strictly necessary
    // because we could just return the maximum of the timestamps that
    // validate sees.  However, the potential cache miss on global time is
    // probably a reasonable price to pay for avoiding unnecessary extensions
    // in the future.
    // We need acquire memory oder because we have to synchronize with the
    // increment of global time by update transactions, whose lock
    // acquisitions we have to observe (also see trycommit()).
    gtm_word snapshot = o_ml_mg.time.load(memory_order_acquire);
    if (!validate(tx)){
      tx->restart(RESTART_VALIDATE_READ);
    }

    // Update our public snapshot time.  Probably useful to decrease waiting
    // due to quiescence-based privatization safety.
    // Use release memory order to establish synchronizes-with with the
    // privatizers; prior data loads should happen before the privatizers
    // potentially modify anything.
    tx->shared_state.store(snapshot, memory_order_release);
    return snapshot;
  }


  /* Write-Back implementation */
  /* ttew */
  static int try_to_extend_with_partial_rollback(gtm_thread* tx) {

    gtm_word snapshot = o_ml_mg.time.load(memory_order_acquire);
      
    gtm_word locked_by_tx = ml_mg::set_locked(tx);

    /* Extend the snapshot, if can not extend or pr is not possible tx would restart */
    tx->shared_state.store(snapshot, memory_order_release);
      
      // gtm_rwlog_entry *r = tx->readlog.begin();
      // gtm_rwlog_entry *rs_end = tx->readlog.end();
    size_t i = 0;

    for (i = 0; i < tx->readlog.size(); i++) {
      gtm_word o = tx->readlog[i].orec->load(memory_order_relaxed);
      
      /* Check if orec is locked*/
      if (ml_mg::is_locked(o)){
        /* Check if orec is locked by tx */
        if (o != locked_by_tx) {
          /* orec is locked by another tx, so read is invalid */
          break;
        }
        else {
          /* Check timestamp */
          if (ml_mg::get_time(o) != ml_mg::get_time(tx->readlog[i].value))
            /* orec has a timestamp different from the one I saved, something changed, so read is invalid */
            break;
        }
      }
    }
    
    printf("%p: TRY TO EXTEND WITH PARTIAL ROLLBACK: fnvr= %d\n", tx,(int)i);
    fflush(stdout);
    
    return i;
    
      
    /*******************************************************************
    for (i = 0 ; r != rs_end; i++, r++){
      //Read lock 
      gtm_word o = r->orec->load(memory_order_relaxed);
          
      //Check if orec is locked
      if (ml_mg::is_locked(o)){
        //Check if orec is locked by tx 
        if (o != locked_by_tx) {
          //orec is locked by another tx, so read is invalid 
          break;
        }
        else {
          //Check timestamp 
          if (ml_mg::get_time(o) != ml_mg::get_time(i->value))
            break;
        }
      }
    }
    return i;
    *******************************************************************/
  }


  // First pass over orecs. Load and check all orecs that cover the region.
  // Write to read log, extend snapshot time if necessary.
  static gtm_rwlog_entry* pre_load(gtm_thread *tx, const void* addr, size_t len) {
	//~ printf("In pre_load before setjmp\n");
	//~ fflush(stdout);
	
	ext_jmpbuf ljb;
	ext_setjmp(&ljb);
	
	//~ printf("In pre_load after setjmp\n");
	//~ fflush(stdout);
	 
    // Don't obtain an iterator yet because the log might get resized.
    size_t log_start = tx->readlog.size();
    gtm_word snapshot = tx->shared_state.load(memory_order_relaxed);
    gtm_word locked_by_tx = ml_mg::set_locked(tx);

	
    ml_mg::orec_iterator oi(addr, len);
    do{
      // We need acquire memory order here so that this load will
      // synchronize with the store that releases the orec in trycommit().
      // In turn, this makes sure that subsequent data loads will read from
      // a visible sequence of side effects that starts with the most recent
      // store to the data right before the release of the orec.
      gtm_word o = o_ml_mg.orecs[oi.get()].load(memory_order_acquire);

      if (likely (!ml_mg::is_more_recent_or_locked(o, snapshot))) {
			    // snapshot > o and non_locked

          success:
          gtm_rwlog_entry *e = tx->readlog.push();
          e->orec = o_ml_mg.orecs + oi.get();
          e->value = o;
          e->next_write_index = tx->writelog.size();  // New entry has first free entry reference of writelog
            
          e->jb = ljb;

      }
      else if (!ml_mg::is_locked(o)) {
        // We cannot read this part of the region because it has been
        // updated more recently than our snapshot time.  If we can extend
        // our snapshot, then we can read.

        // Address-based write index computation

        size_t first_non_valid_read_index = try_to_extend_with_partial_rollback(tx);

        size_t first_non_valid_write_index = tx->readlog[first_non_valid_read_index].next_write_index;

        gtm_rwlog_entry *first_rs_entry = tx->readlog.begin();
        gtm_rwlog_entry *last_rs_entry = tx->readlog.end();

        gtm_rwlog_entry *first_non_valid = &(tx->readlog[first_non_valid_read_index]);

        if (first_non_valid != last_rs_entry) {
          if (first_non_valid == first_rs_entry){
            tx->restart(RESTART_VALIDATE_READ);
          }
          else{
            tx->restart(RESTART_VALIDATE_READ, false, (int)first_non_valid_read_index, (int)first_non_valid_write_index);
          }
        }
        else
          goto success;
      }
      else {
        // L'orec è locked
        // If the orec is locked by us, just skip it because we can just
        // read from it. Otherwise, restart the transaction.
        if ((o != locked_by_tx)){
          // l' orec è locked al tentativo di lettura, devo fare restart
          tx->restart(RESTART_LOCKED_READ);
			  }
      }
      
      oi.advance();
    } while (!oi.reached_end());

    return &tx->readlog[log_start];
  }


  // Second pass over orecs, verifying that the we had a consistent read.
  // Restart the transaction if any of the orecs is locked by another
  // transaction.
  static void post_load(gtm_thread *tx, gtm_rwlog_entry* log){
    for (gtm_rwlog_entry *end = tx->readlog.end(); log != end; log++){
        // Check that the snapshot is consistent.  We expect the previous data
        // load to have acquire memory order, or be atomic and followed by an
        // acquire fence.
        // As a result, the data load will synchronize with the release fence
        // issued by the transactions whose data updates the data load has read
        // from.  This forces the orec load to read from a visible sequence of
        // side effects that starts with the other updating transaction's
        // store that acquired the orec and set it to locked.
        // We therefore either read a value with the locked bit set (and
        // restart) or read an orec value that was written after the data had
        // been written.  Either will allow us to detect inconsistent reads
        // because it will have a higher/different value.
	
        // Also note that differently to validate(), we compare the raw value
        // of the orec here, including incarnation numbers.  We must prevent
        // returning uncommitted data from loads (whereas when validating, we
        // already performed a consistent load).
        gtm_word o = log->orec->load(memory_order_relaxed);
        if (0 && (log->value != o)){
          printf("%p: log->value: %d, o: %d\n", tx, (unsigned int)log->value, (unsigned int)o);
          fflush(stdout);
          tx->restart(RESTART_VALIDATE_READ);
	      }
    }
  }


	long long static current_timestamp() {
		struct timeval te; 
		gettimeofday(&te, NULL); // get current time
		long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
		// printf("milliseconds: %lld\n", milliseconds);
		return milliseconds;
	}


  template <typename V> static V load(const V* addr, ls_modifier mod) {
    // Read-for-write should be unlikely, but we need to handle it or will
    // break later WaW optimizations.

    if (unlikely(mod == RfW)) {
      pre_write(addr, sizeof(V));
      return *addr;
    }
    if (unlikely(mod == RaW))
		return *addr;
    // ??? Optimize for RaR?

    gtm_thread *tx = gtm_thr();
    gtm_rwlog_entry* log = pre_load(tx, addr, sizeof(V));
	
    // Load the data.
    // This needs to have acquire memory order (see post_load()).
    // Alternatively, we can put an acquire fence after the data load but this
    // is probably less efficient.
    // FIXME We would need an atomic load with acquire memory order here but
    // we can't just forge an atomic load for nonatomic data because this
    // might not work on all implementations of atomics.  However, we need
    // the acquire memory order and we can only establish this if we link
    // it to the matching release using a reads-from relation between atomic
    // loads.  Also, the compiler is allowed to optimize nonatomic accesses
    // differently than atomic accesses (e.g., if the load would be moved to
    // after the fence, we potentially don't synchronize properly anymore).
    // Instead of the following, just use an ordinary load followed by an
    // acquire fence, and hope that this is good enough for now:
    // V v = atomic_load_explicit((atomic<V>*)addr, memory_order_acquire);
    V v = *addr;
    atomic_thread_fence(memory_order_acquire);


    //printf("%p: reading address %p, value = %d, current-timestamp = %lld\n", tx, addr, (int)*((int*)addr), current_timestamp());
    //fflush(stdout);

    post_load(tx, log);
	
    return v;
  }


  template <typename V> static void store(V* addr, const V value, ls_modifier mod) {
    if (likely(mod != WaW))
      pre_write(addr, sizeof(V));
    // FIXME We would need an atomic store here but we can't just forge an
    // atomic load for nonatomic data because this might not work on all
    // implementations of atomics.  However, we need this store to link the
    // release fence in pre_write() to the acquire operation in load, which
    // is only guaranteed if we have a reads-from relation between atomic
    // accesses.  Also, the compiler is allowed to optimize nonatomic accesses
    // differently than atomic accesses (e.g., if the store would be moved
    // to before the release fence in pre_write(), things could go wrong).
    // atomic_store_explicit((atomic<V>*)addr, value, memory_order_relaxed);
    //gtm_thread *tx = gtm_thr();
    //printf("%p: writing address %p\n", tx, addr);
	  //fflush(stdout);
    *addr = value;
  }


public:
  static void memtransfer_static(void *dst, const void* src, size_t size, bool may_overlap, ls_modifier dst_mod, ls_modifier src_mod) {
    gtm_rwlog_entry* log = 0;
    gtm_thread *tx = 0;

    if (src_mod == RfW)
      {
        tx = gtm_thr();
        pre_write(tx, src, size);
      }
    else if (src_mod != RaW && src_mod != NONTXNAL)
      {
        tx = gtm_thr();
        log = pre_load(tx, src, size);
      }
    // ??? Optimize for RaR?

    if (dst_mod != NONTXNAL && dst_mod != WaW)
      {
        if (src_mod != RfW && (src_mod == RaW || src_mod == NONTXNAL))
          tx = gtm_thr();
        pre_write(tx, dst, size);
      }

    // FIXME We should use atomics here (see store()).  Let's just hope that
    // memcpy/memmove are good enough.
    if (!may_overlap)
      ::memcpy(dst, src, size);
    else
      ::memmove(dst, src, size);

    // ??? Retry the whole memtransfer if it wasn't consistent?
    if (src_mod != RfW && src_mod != RaW && src_mod != NONTXNAL){
      // See load() for why we need the acquire fence here.
      atomic_thread_fence(memory_order_acquire);
      post_load(tx, log);
    }
  }


  static void memset_static(void *dst, int c, size_t size, ls_modifier mod) {
    if (mod != WaW)
      pre_write(dst, size);
    // FIXME We should use atomics here (see store()).  Let's just hope that
    // memset is good enough.
    ::memset(dst, c, size);
  }


  virtual gtm_restart_reason begin_or_restart() {
    // We don't need to do anything for nested transactions.
    gtm_thread *tx = gtm_thr();
    if (tx->parent_txns.size() > 0)
      return NO_RESTART;

    // Read the current time, which becomes our snapshot time.
    // Use acquire memory oder so that we see the lock acquisitions by update
    // transcations that incremented the global time (see trycommit()).
    gtm_word snapshot = o_ml_mg.time.load(memory_order_acquire);
    // Re-initialize method group on time overflow.
    if (snapshot >= o_ml_mg.TIME_MAX)
      return RESTART_INIT_METHOD_GROUP;

    // We don't need to enforce any ordering for the following store. There
    // are no earlier data loads in this transaction, so the store cannot
    // become visible before those (which could lead to the violation of
    // privatization safety). The store can become visible after later loads
    // but this does not matter because the previous value will have been
    // smaller or equal (the serial lock will set shared_state to zero when
    // marking the transaction as active, and restarts enforce immediate
    // visibility of a smaller or equal value with a barrier (see
    // rollback()).
    tx->shared_state.store(snapshot, memory_order_relaxed);
    return NO_RESTART;
  }


  virtual bool trycommit(gtm_word& priv_time) {
    gtm_thread* tx = gtm_thr();

    // If we haven't updated anything (transazione read-only), we can commit.
    if (!tx->writelog.size()){
        tx->readlog.clear();
        /* We still need to ensure privatization safety, unfortunately.  While
          we cannot have privatized anything by ourselves (because we are not
          an update transaction), we can have observed the commits of
          another update transaction that privatized something.  Because any
          commit happens before ensuring privatization, our snapshot and
          commit can thus have happened before ensuring privatization safety
          for this commit/snapshot time.  Therefore, before we can return to
          nontransactional code that might use the privatized data, we must
          ensure privatization safety for our snapshot time.
          This still seems to be better than not allowing use of the
          snapshot time before privatization safety has been ensured because
          we at least can run transactions such as this one, and in the
          meantime the transaction producing this commit time might have
          finished ensuring privatization safety for it. */
        priv_time = tx->shared_state.load(memory_order_relaxed);
        return true;
    }

    /* Get a commit time.
       Overflow of o_ml_mg.time is prevented in begin_or_restart().
       We need acq_rel here because (1) the acquire part is required for our
       own subsequent call to validate(), and the release part is necessary to
       make other threads' validate() work as explained there and in extend(). */
    gtm_word ct = o_ml_mg.time.fetch_add(1, memory_order_acq_rel) + 1;

    /* Extend our snapshot time to at least our commit time.
       Note that we do not need to validate if our snapshot time is right
       before the commit time because we are never sharing the same commit
       time with other transactions.
       No need to reset shared_state, which will be modified by the serial
       lock right after our commit anyway. */
    gtm_word snapshot = tx->shared_state.load(memory_order_relaxed);
    if (snapshot < ct - 1 && !validate(tx)){
      return false;
	  }

    /* Release orecs.
       See pre_load() / post_load() for why we need release memory order.
       ??? Can we use a release fence and relaxed stores? */
    gtm_word v = ml_mg::set_time(ct);
    for (gtm_rwlog_entry *i = tx->writelog.begin(), *ie = tx->writelog.end(); i != ie; i++)
      i->orec->store(v, memory_order_release);

    // We're done, clear the logs.
    tx->writelog.clear();
    tx->readlog.clear();

    /* Need to ensure privatization safety. Every other transaction must
       have a snapshot time that is at least as high as our commit time
       (i.e., our commit must be visible to them). */
    priv_time = ct;
    return true;
  }

  virtual void partial_rollback(gtm_transaction_cp *cp, int r_i, int w_i) {
	  // We don't do anything for rollbacks of nested transactions.
    // ??? We could release locks here if we snapshot writelog size.  readlog
    // is similar.  This is just a performance optimization though.  Nested
    // aborts should be rather infrequent, so the additional save/restore
    // overhead for the checkpoints could be higher.
    if (cp != 0)
      return;
    
    gtm_thread *tx = gtm_thr();
    gtm_word overflow_value = 0;
    
    printf("%p: PR: Partial rollback... r_i: %d, w_i %d\n", tx, r_i, w_i);
    fflush(stdout);

    // Release orecs.
    for (size_t i = w_i; i < tx->writelog.size(); i++) {
      printf("%p: PR: i=%ld, size= %ld\n", tx, i, tx->writelog.size());
      fflush(stdout);
      
      if (ml_mg::has_incarnation_left(tx->writelog[i].value)){
        printf("%p: PR: if\n", tx );
        fflush(stdout);
        tx->writelog[i].orec->store(ml_mg::inc_incarnation(tx->writelog[i].value), memory_order_release);
        printf("%p: PR: end if\n", tx );
        fflush(stdout);
      }
      else {
        printf("%p: PR: else\n", tx );
        fflush(stdout);
              
        if (!overflow_value){
          printf("%p: PR: not overflow\n", tx );
          fflush(stdout);
          overflow_value = ml_mg::set_time(o_ml_mg.time.fetch_add(1, memory_order_release) + 1);
        }
        
        tx->writelog[i].orec->store(overflow_value, memory_order_release);
        printf("%p: PR: end else\n", tx );
        fflush(stdout);
      }
    }
    
    /*
      for (gtm_rwlog_entry *i = start, *ie = tx->writelog.end(); i != ie; i++) {
      printf("%p: PR: start: %p, end:%p\n", tx, start, tx->writelog.end() );
      fflush(stdout);
      printf("%p: PR: iteration\n", tx );
      fflush(stdout);
          // If possible, just increase the incarnation number.
          // See pre_load() / post_load() for why we need release memory order.
      // ??? Can we use a release fence and relaxed stores?  (Same below.)
          if (ml_mg::has_incarnation_left(i->value)){
        printf("%p: PR: if\n", tx );
        fflush(stdout);
        i->orec->store(ml_mg::inc_incarnation(i->value), memory_order_release);
        printf("%p: PR: end if\n", tx );
        fflush(stdout);
        }
          else
            {
        printf("%p: PR: else\n", tx );
        fflush(stdout);
              // We have an incarnation overflow.  Acquire a new timestamp, and
              // use it from now on as value for each orec whose incarnation
              // number cannot be increased.
              // Overflow of o_ml_mg.time is prevented in begin_or_restart().
              // See pre_load() / post_load() for why we need release memory
              // order.
              if (!overflow_value){
                // Release memory order is sufficient but required here.
                // In contrast to the increment in trycommit(), we need release
                // for the same reason but do not need the acquire because we
                // do not validate subsequently.
                printf("%p: PR: not overflow\n", tx );
          fflush(stdout);
                overflow_value = ml_mg::set_time(o_ml_mg.time.fetch_add(1, memory_order_release) + 1);
        }
              i->orec->store(overflow_value, memory_order_release);
              printf("%p: PR: end else\n", tx );
        fflush(stdout);
            }
        }
        */

    // We need this release fence to ensure that privatizers see the
    // rolled-back original state (not any uncommitted values) when they read
    // the new snapshot time that we write in begin_or_restart().
    
    atomic_thread_fence(memory_order_release);

    printf("%p: PR: readlog size = %ld, writelog size = %ld\n", tx, tx->readlog.size(), tx->writelog.size());
    fflush(stdout);
    
    // We're done, clear the logs.
    if (tx->readlog.size() - r_i < 0)
      tx->readlog.clear();
    else
      tx->readlog.set_size(tx->writelog.size() - w_i);
    
    if (tx->writelog.size() - w_i < 0)
      tx->writelog.clear();
    else
      tx->writelog.set_size(tx->writelog.size() - w_i);
    
    printf("%p: PR: cleared\n", tx );
    fflush(stdout);
  }

  virtual void rollback(gtm_transaction_cp *cp) {
    printf("### CALLED method-pr.cc  ->  rollback() ###\n");
    // We don't do anything for rollbacks of nested transactions.
    // ??? We could release locks here if we snapshot writelog size.  readlog
    // is similar.  This is just a performance optimization though.  Nested
    // aborts should be rather infrequent, so the additional save/restore
    // overhead for the checkpoints could be higher.
    if (cp != 0)
      return;
    
    gtm_thread *tx = gtm_thr();
    gtm_word overflow_value = 0;
    
    // Release orecs.
    for (gtm_rwlog_entry *i = tx->writelog.begin(), *ie = tx->writelog.end(); i != ie; i++) {
        // If possible, just increase the incarnation number.
        // See pre_load() / post_load() for why we need release memory order.
	    // ??? Can we use a release fence and relaxed stores?  (Same below.)
      if (ml_mg::has_incarnation_left(i->value))
         i->orec->store(ml_mg::inc_incarnation(i->value), memory_order_release);
      else{
        // We have an incarnation overflow.  Acquire a new timestamp, and
        // use it from now on as value for each orec whose incarnation
        // number cannot be increased.
        // Overflow of o_ml_mg.time is prevented in begin_or_restart().
        // See pre_load() / post_load() for why we need release memory
        // order.
        if (!overflow_value)
          // Release memory order is sufficient but required here.
          // In contrast to the increment in trycommit(), we need release
          // for the same reason but do not need the acquire because we
          // do not validate subsequently.
          overflow_value = ml_mg::set_time(
                  o_ml_mg.time.fetch_add(1, memory_order_release) + 1);
            i->orec->store(overflow_value, memory_order_release);
        }
    }

    // We need this release fence to ensure that privatizers see the
    // rolled-back original state (not any uncommitted values) when they read
    // the new snapshot time that we write in begin_or_restart().
    atomic_thread_fence(memory_order_release);

    // We're done, clear the logs.
    tx->writelog.clear();
    tx->readlog.clear();
  }


  virtual bool snapshot_most_recent(){
    // This is the same code as in extend() except that we do not restart
    // on failure but simply return the result, and that we don't validate
    // if our snapshot is already most recent.
    gtm_thread* tx = gtm_thr();
    gtm_word snapshot = o_ml_mg.time.load(memory_order_acquire);
    if (snapshot == tx->shared_state.load(memory_order_relaxed))
      return true;
    if (!validate(tx))
      return false;

    // Update our public snapshot time.  Necessary so that we do not prevent
    // other transactions from ensuring privatization safety.
    tx->shared_state.store(snapshot, memory_order_release);
    return true;
  }


  virtual bool supports(unsigned number_of_threads){
    // Each txn can commit and fail and rollback once before checking for
    // overflow, so this bounds the number of threads that we can support.
    // In practice, this won't be a problem but we check it anyway so that
    // we never break in the occasional weird situation.
    return (number_of_threads * 2 <= ml_mg::OVERFLOW_RESERVE);
  }


  CREATE_DISPATCH_METHODS(virtual, )
  CREATE_DISPATCH_METHODS_MEM()

  ml_wt_pr_dispatch() : abi_dispatch(false, true, false, false, 0, &o_ml_mg) { }
};

} // anonymous namespace

static const ml_wt_pr_dispatch o_ml_wt_pr_dispatch;

abi_dispatch *GTM::dispatch_ml_wt_pr () {
  return const_cast<ml_wt_pr_dispatch *>(&o_ml_wt_pr_dispatch);
}
