//! The distributed task's join protocol on its word: one join waker,
//! publication waking it once, the outcome taken once, and detaching
//! before or after publication.

use super::super::identity::TaskId;
use super::super::{AbortHandle, AsyncJoinError};
use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Poll, Wake};

struct CountWake(Arc<AtomicUsize>);

impl Wake for CountWake {
  fn wake(self: Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

/// Counts its drops; used as the task output.
struct Output(Arc<AtomicUsize>);

impl Drop for Output {
  fn drop(&mut self) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

fn create<F>(future: F) -> (Pin<Arc<dyn ErasedTask>>, AsyncJob<F::Output>)
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  let admission = Task::<F>::reserve_domain_admission(None).unwrap();
  Task::create(
    future,
    TaskId::test_sentinel(),
    None,
    admission,
    Weak::new(),
    TaskRef::test_sentinel(),
  )
}

/// Runs the task's final turn outside a scheduler: a ready poll, then
/// publication.
fn complete(task: &Pin<Arc<dyn ErasedTask>>) {
  let permit = PollPermit {
    release: PermitRelease::Free,
  };
  let result = {
    let turn = task.as_ref().test_turn().unwrap();
    task.as_ref().poll(
      &turn.key(),
      &mut Context::from_waker(Waker::noop()),
      permit,
      &mut None,
    )
  };
  assert!(matches!(result, (PollResult::Ready, None)));
  task.publish();
}

fn counter() -> (Arc<AtomicUsize>, Waker) {
  let count = Arc::new(AtomicUsize::new(0));
  let waker = Waker::from(Arc::new(CountWake(Arc::clone(&count))));
  (count, waker)
}

fn poll<T>(job: &mut AsyncJob<T>, waker: &Waker) -> Poll<Result<T, AsyncJoinError>> {
  Pin::new(job).poll(&mut Context::from_waker(waker))
}

#[test]
fn registration_before_completion_is_woken_once_and_takes_the_output_once() {
  let drops = Arc::new(AtomicUsize::new(0));
  let (task, mut job) = create(std::future::ready(Output(Arc::clone(&drops))));
  let (wakes, waker) = counter();
  assert!(poll(&mut job, &waker).is_pending());
  assert_eq!(task.poll_word().join_flags(), (true, true));
  complete(&task);
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert!(job.is_finished());
  let Poll::Ready(Ok(output)) = poll(&mut job, &waker) else {
    panic!("published output was not returned");
  };
  // A second poll after the take reports no output again.
  assert!(matches!(
    poll(&mut job, &waker),
    Poll::Ready(Err(AsyncJoinError::Cancelled))
  ));
  drop(output);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  drop(job);
  drop(task);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
}

#[test]
fn reregistration_keeps_a_matching_waker_and_replaces_a_different_one() {
  let (task, mut job) = create(std::future::ready(3usize));
  let (wakes_a, _) = counter();
  let (wakes_b, _) = counter();
  let wake_a = Arc::new(CountWake(Arc::clone(&wakes_a)));
  let wake_b = Arc::new(CountWake(Arc::clone(&wakes_b)));
  let waker_a = Waker::from(Arc::clone(&wake_a));
  let waker_b = Waker::from(Arc::clone(&wake_b));
  assert!(poll(&mut job, &waker_a).is_pending());
  assert_eq!(Arc::strong_count(&wake_a), 3);
  // `will_wake` keeps the stored waker without a clone.
  assert!(poll(&mut job, &waker_a).is_pending());
  assert_eq!(Arc::strong_count(&wake_a), 3);
  assert!(poll(&mut job, &waker_b).is_pending());
  assert_eq!(Arc::strong_count(&wake_a), 2);
  assert_eq!(Arc::strong_count(&wake_b), 3);
  complete(&task);
  assert_eq!(wakes_a.load(Ordering::SeqCst), 0);
  assert_eq!(wakes_b.load(Ordering::SeqCst), 1);
  assert!(matches!(poll(&mut job, &waker_b), Poll::Ready(Ok(3))));
  drop(job);
  // The stored waker went with the detached handle.
  assert_eq!(Arc::strong_count(&wake_b), 2);
}

#[test]
fn registration_after_publication_takes_the_output_without_storing_a_waker() {
  let (task, mut job) = create(std::future::ready(5usize));
  complete(&task);
  let wake = Arc::new(CountWake(Arc::new(AtomicUsize::new(0))));
  let waker = Waker::from(Arc::clone(&wake));
  assert!(matches!(poll(&mut job, &waker), Poll::Ready(Ok(5))));
  assert_eq!(Arc::strong_count(&wake), 2);
  assert_eq!(task.poll_word().join_flags(), (true, false));
}

#[test]
fn detaching_before_publication_leaves_the_output_to_the_publisher() {
  let drops = Arc::new(AtomicUsize::new(0));
  let (task, mut job) = create(std::future::ready(Output(Arc::clone(&drops))));
  let wake = Arc::new(CountWake(Arc::new(AtomicUsize::new(0))));
  let waker = Waker::from(Arc::clone(&wake));
  assert!(poll(&mut job, &waker).is_pending());
  let abort = job.abort_handle();
  drop(job);
  // The handle took its waker back; JOIN_INTEREST and JOIN_WAKER are clear.
  assert_eq!(Arc::strong_count(&wake), 2);
  assert_eq!(task.poll_word().join_flags(), (false, false));
  assert!(!abort.is_finished());
  complete(&task);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert!(abort.is_finished());
}

#[test]
fn detaching_after_publication_drops_the_output_in_the_handle() {
  let drops = Arc::new(AtomicUsize::new(0));
  let (task, mut job) = create(std::future::ready(Output(Arc::clone(&drops))));
  let wake = Arc::new(CountWake(Arc::new(AtomicUsize::new(0))));
  let waker = Waker::from(Arc::clone(&wake));
  assert!(poll(&mut job, &waker).is_pending());
  complete(&task);
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(job);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert_eq!(Arc::strong_count(&wake), 2);
  drop(task);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_and_resource_failure_publish_through_the_one_waker() {
  for fail in [false, true] {
    let (task, mut job) = create(std::future::pending::<usize>());
    let (wakes, waker) = counter();
    assert!(poll(&mut job, &waker).is_pending());
    {
      let turn = task.as_ref().test_turn().unwrap();
      if fail {
        task.as_ref().fail_resource(
          &turn.key(),
          crate::runtime::resource_domain::DomainError::WaitersFull,
        );
      } else {
        task.as_ref().cancel(&turn.key());
      }
    }
    // Storing the outcome leaves the join bits and the waker alone.
    assert_eq!(task.poll_word().join_flags(), (true, true));
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    assert!(!job.is_finished());
    task.publish();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    let outcome = poll(&mut job, &waker);
    if fail {
      assert!(matches!(
        outcome,
        Poll::Ready(Err(AsyncJoinError::ResourceDomain(_)))
      ));
    } else {
      assert!(matches!(
        outcome,
        Poll::Ready(Err(AsyncJoinError::Cancelled))
      ));
    }
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
  }
}

#[test]
fn panicking_poll_publishes_the_panic_once() {
  let (task, mut job) = create(async {
    panic!("join word panic");
  });
  let (wakes, waker) = counter();
  assert!(poll(&mut job, &waker).is_pending());
  complete(&task);
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert!(matches!(
    poll(&mut job, &waker),
    Poll::Ready(Err(AsyncJoinError::Panicked(_)))
  ));
}

#[test]
fn registration_racing_publication_is_never_lost() {
  for round in 0..2000 {
    let (task, mut job) = create(std::future::ready(round));
    let (wakes, waker) = counter();
    let publisher = std::thread::spawn(move || complete(&task));
    let ready = match poll(&mut job, &waker) {
      Poll::Ready(outcome) => {
        assert_eq!(outcome.unwrap(), round);
        true
      }
      Poll::Pending => false,
    };
    publisher.join().unwrap();
    if !ready {
      assert_eq!(wakes.load(Ordering::SeqCst), 1);
      assert!(matches!(poll(&mut job, &waker), Poll::Ready(Ok(r)) if r == round));
    }
    assert!(wakes.load(Ordering::SeqCst) <= 1);
  }
}

#[test]
fn detach_racing_publication_drops_output_and_waker_once() {
  struct DropWake(Arc<AtomicUsize>);
  // Waker::noop cannot count its drops.
  #[allow(clippy::manual_noop_waker)]
  impl Wake for DropWake {
    fn wake(self: Arc<Self>) {}
  }
  impl Drop for DropWake {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }
  for _ in 0..2000 {
    let drops = Arc::new(AtomicUsize::new(0));
    let waker_drops = Arc::new(AtomicUsize::new(0));
    let (task, mut job) = create(std::future::ready(Output(Arc::clone(&drops))));
    let waker = Waker::from(Arc::new(DropWake(Arc::clone(&waker_drops))));
    assert!(poll(&mut job, &waker).is_pending());
    drop(waker);
    let publisher = std::thread::spawn(move || complete(&task));
    drop(job);
    publisher.join().unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(waker_drops.load(Ordering::SeqCst), 1);
  }
}

/// Polls that run long enough for aborts and a cancelling close to land
/// while dispatchers hold their turns: each task is cleaned up once, every
/// join resolves, and no turn outlives the runtime.
#[test]
fn abort_and_close_during_running_polls_clean_up_each_task_once() {
  use super::super::{AsyncConfig, AsyncRuntime, AsyncShutdown};

  struct Spin {
    polls: usize,
    drops: Arc<AtomicUsize>,
    running: Arc<AtomicUsize>,
  }

  impl Future for Spin {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
      self.running.fetch_add(1, Ordering::SeqCst);
      for _ in 0..200 {
        std::hint::spin_loop();
      }
      self.polls += 1;
      if self.polls == 400 {
        return Poll::Ready(self.polls);
      }
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  }

  impl Drop for Spin {
    fn drop(&mut self) {
      self.drops.fetch_add(1, Ordering::SeqCst);
    }
  }

  const TASKS: usize = 16;
  for round in 0..40 {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 4,
      max_outstanding: TASKS,
      max_scopes: 1,
    })
    .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicUsize::new(0));
    let mut jobs: Vec<_> = (0..TASKS)
      .map(|_| {
        runtime
          .handle()
          .spawn(Spin {
            polls: 0,
            drops: Arc::clone(&drops),
            running: Arc::clone(&running),
          })
          .unwrap()
      })
      .collect();
    let aborts: Vec<_> = jobs
      .iter()
      .enumerate()
      .filter(|(index, _)| (index + round) % 2 == 0)
      .map(|(_, job)| job.abort_handle())
      .collect();
    let aborter = {
      let running = Arc::clone(&running);
      std::thread::spawn(move || {
        while running.load(Ordering::SeqCst) < TASKS {
          std::thread::yield_now();
        }
        for abort in &aborts {
          abort.abort();
        }
        aborts
      })
    };
    while running.load(Ordering::SeqCst) < TASKS * 2 {
      std::thread::yield_now();
    }
    runtime.shutdown(AsyncShutdown::CancelPending).unwrap();
    let aborts = aborter.join().unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), TASKS);
    for job in &mut jobs {
      assert!(job.is_finished());
      match poll(job, Waker::noop()) {
        Poll::Ready(Ok(400) | Err(AsyncJoinError::Cancelled)) => {}
        other => panic!("unexpected outcome {:?}", other.map(|r| r.map(drop))),
      }
    }
    assert!(aborts.iter().all(AbortHandle::is_finished));
  }
}

fn poll_finished<T>(job: &mut AsyncJob<T>, waker: &Waker) -> Poll<()> {
  Pin::new(job).poll_finished(&mut Context::from_waker(waker))
}

#[test]
fn join_and_finished_waiters_are_both_woken_once() {
  let (task, mut job) = create(std::future::ready(8usize));
  let (join_wakes, join_waker) = counter();
  let (finished_wakes, finished_waker) = counter();
  let (late_wakes, late_waker) = counter();
  assert!(poll_finished(&mut job, &finished_waker).is_pending());
  assert!(poll(&mut job, &join_waker).is_pending());
  // Re-registering each slot keeps the other slot's waker.
  assert!(poll(&mut job, &join_waker).is_pending());
  assert!(poll_finished(&mut job, &late_waker).is_pending());
  assert!(poll(&mut job, &join_waker).is_pending());
  complete(&task);
  assert_eq!(join_wakes.load(Ordering::SeqCst), 1);
  assert_eq!(late_wakes.load(Ordering::SeqCst), 1);
  assert_eq!(finished_wakes.load(Ordering::SeqCst), 0);
  // After completion both report ready without registering.
  assert!(poll_finished(&mut job, &finished_waker).is_ready());
  assert!(matches!(job.take_finished(), Some(Ok(8))));
  assert!(matches!(
    poll(&mut job, &join_waker),
    Poll::Ready(Err(AsyncJoinError::Cancelled))
  ));
  assert_eq!(task.poll_word().join_flags(), (true, false));
}

#[test]
fn finished_waiter_registered_alone_is_woken_by_cancellation_publication() {
  let (task, mut job) = create(std::future::pending::<usize>());
  let (wakes, waker) = counter();
  assert!(poll_finished(&mut job, &waker).is_pending());
  {
    let turn = task.as_ref().test_turn().unwrap();
    task.as_ref().cancel(&turn.key());
  }
  assert_eq!(wakes.load(Ordering::SeqCst), 0);
  task.publish();
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert!(poll_finished(&mut job, &waker).is_ready());
  assert!(matches!(
    poll(&mut job, &waker),
    Poll::Ready(Err(AsyncJoinError::Cancelled))
  ));
}

#[test]
fn join_and_finished_registrations_racing_publication_wake_every_pending_waiter() {
  for round in 0..2000 {
    let (task, mut job) = create(std::future::ready(round));
    let (join_wakes, join_waker) = counter();
    let (finished_wakes, finished_waker) = counter();
    let (moved_wakes, moved_waker) = counter();
    let publisher = std::thread::spawn(move || complete(&task));
    // Register in alternating orders, then move the completion-only waiter.
    let (first, second, third) = if round % 2 == 0 {
      let first = poll_finished(&mut job, &finished_waker).is_pending();
      let second = poll(&mut job, &join_waker);
      let third = poll_finished(&mut job, &moved_waker).is_pending();
      (first, second, third)
    } else {
      let second = poll(&mut job, &join_waker);
      let first = poll_finished(&mut job, &finished_waker).is_pending();
      let third = poll_finished(&mut job, &moved_waker).is_pending();
      (first, second, third)
    };
    publisher.join().unwrap();
    let join = join_wakes.load(Ordering::SeqCst);
    let finished = finished_wakes.load(Ordering::SeqCst);
    let moved = moved_wakes.load(Ordering::SeqCst);
    assert!(join <= 1 && finished <= 1 && moved <= 1, "woken twice");
    if second.is_pending() {
      assert_eq!(join, 1, "pending join waiter not woken");
    }
    // The completion-only role is one waiter: its latest pending
    // registration is woken; a re-registration that returned ready already
    // observed completion.
    assert!(finished + moved <= 1, "completion-only waiter woken twice");
    if third {
      assert_eq!(moved, 1, "pending completion-only waiter not woken");
    } else if first && finished == 0 {
      assert!(job.is_finished());
    }
    let outcome = match second {
      Poll::Ready(outcome) => outcome,
      Poll::Pending => match poll(&mut job, Waker::noop()) {
        Poll::Ready(outcome) => outcome,
        Poll::Pending => panic!("woken without a published outcome"),
      },
    };
    assert_eq!(outcome.unwrap(), round);
  }
}
