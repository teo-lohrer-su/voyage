use std::{
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use caracat::{models::Reply, receiver::Receiver};

pub struct ReceiveCache {
    handle: JoinHandle<()>,
    stopped: Arc<Mutex<bool>>,
    pub replies: Arc<Mutex<Vec<Reply>>>,
}

impl ReceiveCache {
    pub fn new(
        interface: String,
    ) -> Self {
        let stopped = Arc::new(Mutex::new(false));
        let stopped_thr = stopped.clone();
        let replies = Arc::new(Mutex::new(Vec::new()));
        let replies_thread = replies.clone();

        let handle = thread::spawn(move || {
            let mut receiver = Receiver::new_batch(&interface).unwrap();

            loop {
                let reply = receiver.next_reply();
                if let Ok(reply) = reply {
                    replies_thread.lock().unwrap().push(reply);
                }

                if *stopped_thr.lock().unwrap() {
                    break;
                }
            }
        });

        ReceiveCache {
            handle,
            stopped,
            replies,
        }
    }

    pub fn stop(&mut self) -> Vec<Reply>{
        *self.stopped.lock().unwrap() = true;
        //  // Wait for the thread to finish
        //  if let Some(handle) = self.handle.take() {
        //     handle.join().unwrap();
        // }

        // Drain the replies vector
        self.replies.lock().unwrap().drain(..).collect()
    }
}
