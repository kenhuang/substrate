// Copyright 2017-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Chain utilities.

use std::{self, io::{Read, Write}};
use futures::Future;
use log::{info, warn};

use runtime_primitives::generic::{SignedBlock, BlockId};
use runtime_primitives::generic::Era;
use runtime_primitives::traits::{As, Block, Header, NumberFor, ProvideRuntimeApi, BlockNumberToHash, Extrinsic};
use runtime_primitives::OpaqueExtrinsic;
use primitives::{ed25519, sr25519};
use consensus_common::import_queue::{ImportQueue, IncomingBlock, Link};
use consensus_common::ForkChoiceStrategy;
use std::collections::HashMap;
use consensus_common::ImportBlock;
use network::message;
use node_runtime::{Call, Runtime, Balances, UncheckedExtrinsic, CheckedExtrinsic};
use sr_io;
use primitives::crypto::Pair;

use keyring::ed25519::Keyring;
use keyring::sr25519::Keyring as srKeyring;
use balances::Call as BalancesCall;
use indices;

use consensus_common::BlockOrigin;
use crate::components::{self, Components, ServiceFactory, FactoryFullConfiguration, FactoryBlockNumber, RuntimeGenesis, FullClient};
use crate::{new_client, FactoryBlock};
use parity_codec::{Decode, Encode};
use crate::error;
use crate::chain_spec::ChainSpec;
use client::runtime_api::ConstructRuntimeApi;
use std::sync::Arc;

use client::Client;
use client::LocalCallExecutor;
use substrate_executor::NativeExecutor;
use client::blockchain::Backend;
use consensus_common::block_import::BlockImport;
use client::block_builder::api::BlockBuilder;

/// Export a range of blocks to a binary stream.
pub fn export_blocks<F, E, W>(
	config: FactoryFullConfiguration<F>,
	exit: E,
	mut output: W,
	from: FactoryBlockNumber<F>,
	to: Option<FactoryBlockNumber<F>>,
	json: bool
) -> error::Result<()>
	where
	F: ServiceFactory,
	E: Future<Item=(),Error=()> + Send + 'static,
	W: Write,
{
	let client = new_client::<F>(&config)?;
	let mut block = from;

	let last = match to {
		Some(v) if v == As::sa(0) => As::sa(1),
		Some(v) => v,
		None => client.info()?.chain.best_number,
	};

	if last < block {
		return Err("Invalid block range specified".into());
	}

	let (exit_send, exit_recv) = std::sync::mpsc::channel();
	::std::thread::spawn(move || {
		let _ = exit.wait();
		let _ = exit_send.send(());
	});
	info!("Exporting blocks from #{} to #{}", block, last);
	if !json {
		let last_: u64 = last.as_();
		let block_: u64 = block.as_();
		let len: u64 = last_ - block_ + 1;
		output.write(&len.encode())?;
	}

	loop {
		if exit_recv.try_recv().is_ok() {
			break;
		}
		match client.block(&BlockId::number(block))? {
			Some(block) => {
				if json {
					serde_json::to_writer(&mut output, &block)
						.map_err(|e| format!("Error writing JSON: {}", e))?;
				} else {
					output.write(&block.encode())?;
				}
			},
			None => break,
		}
		if block.as_() % 10000 == 0 {
			info!("#{}", block);
		}
		if block == last {
			break;
		}
		block += As::sa(1);
	}
	Ok(())
}

struct WaitLink {
	wait_send: std::sync::mpsc::Sender<()>,
}

impl WaitLink {
	fn new(wait_send: std::sync::mpsc::Sender<()>) -> WaitLink {
		WaitLink {
			wait_send,
		}
	}
}

impl<B: Block> Link<B> for WaitLink {
	fn block_imported(&self, _hash: &B::Hash, _number: NumberFor<B>) {
		self.wait_send.send(())
			.expect("Unable to notify main process; if the main process panicked then this thread would already be dead as well. qed.");
	}
}

/// Import blocks from a binary stream.
pub fn import_blocks<F, E, R>(
	mut config: FactoryFullConfiguration<F>,
	exit: E,
	mut input: R
) -> error::Result<()>
	where F: ServiceFactory, E: Future<Item=(),Error=()> + Send + 'static, R: Read,
{
	let client = new_client::<F>(&config)?;
	// FIXME #1134 this shouldn't need a mutable config.
	let queue = components::FullComponents::<F>::build_import_queue(&mut config, client.clone())?;

	let (wait_send, wait_recv) = std::sync::mpsc::channel();
	let wait_link = WaitLink::new(wait_send);
	queue.start(Box::new(wait_link))?;

	let (exit_send, exit_recv) = std::sync::mpsc::channel();
	::std::thread::spawn(move || {
		let _ = exit.wait();
		let _ = exit_send.send(());
	});

	let count: u64 = Decode::decode(&mut input).ok_or("Error reading file")?;
	info!("Importing {} blocks", count);
	let mut block_count = 0;
	for b in 0 .. count {
		if exit_recv.try_recv().is_ok() {
			break;
		}
		if let Some(signed) = SignedBlock::<F::Block>::decode(&mut input) {
			let (header, extrinsics) = signed.block.deconstruct();
			let hash = header.hash();
			let block  = message::BlockData::<F::Block> {
				hash: hash,
				justification: signed.justification,
				header: Some(header),
				body: Some(extrinsics),
				receipt: None,
				message_queue: None
			};
			// import queue handles verification and importing it into the client
			queue.import_blocks(BlockOrigin::File, vec![
				IncomingBlock::<F::Block>{
					hash: block.hash,
					header: block.header,
					body: block.body,
					justification: block.justification,
					origin: None,
				}
			]);
		} else {
			warn!("Error reading block data at {}.", b);
			break;
		}

		block_count = b;
		if b % 1000 == 0 {
			info!("#{}", b);
		}
	}

	let mut blocks_imported = 0;
	while blocks_imported < count {
		wait_recv.recv()
			.expect("Importing thread has panicked. Then the main process will die before this can be reached. qed.");
		blocks_imported += 1;
	}

	info!("Imported {} blocks. Best: #{}", block_count, client.info()?.chain.best_number);

	Ok(())
}

/// Revert the chain.
pub fn revert_chain<F>(
	config: FactoryFullConfiguration<F>,
	blocks: FactoryBlockNumber<F>
) -> error::Result<()>
	where F: ServiceFactory,
{
	let client = new_client::<F>(&config)?;
	let reverted = client.revert(blocks)?;
	let info = client.info()?.chain;

	if reverted.as_() == 0 {
		info!("There aren't any non-finalized blocks to revert.");
	} else {
		info!("Reverted {} blocks. Best: #{} ({})", reverted, info.best_number, info.best_hash);
	}
	Ok(())
}

/// Factory
pub fn factory<F>(
	config: FactoryFullConfiguration<F>,
	blocks: FactoryBlockNumber<F>
) -> error::Result<()>
	where
		F: ServiceFactory,
		F::RuntimeApi: ConstructRuntimeApi<FactoryBlock<F>, FullClient<F>>,
		FullClient<F>: ProvideRuntimeApi,
		<FullClient<F> as ProvideRuntimeApi>::Api: BlockBuilder<FactoryBlock<F>>
{
	let client = new_client::<F>(&config)?;

	let api = client.runtime_api();

	let alice: node_primitives::AccountId = srKeyring::Alice.into();
	let bob: node_primitives::AccountId = srKeyring::Bob.into();

    fn sign<F: ServiceFactory>(xt: CheckedExtrinsic, client: &FullClient<F>) -> UncheckedExtrinsic {
		match xt.signed {
			Some((signed, index)) => {
				let era = Era::mortal(256, 0);
				let payload = (index.into(), xt.function, era, client.genesis_hash());
				let key = srKeyring::from_public(&signed).unwrap();
				let signature = payload.using_encoded(|b| {
					if b.len() > 256 {
						key.sign(&sr_io::blake2_256(b))
					} else {
						key.sign(b)
					}
				}).into();
				UncheckedExtrinsic {
					signature: Some((indices::address::Address::Id(signed), signature, payload.0, era)),
					function: payload.1,
				}
			}
			None => UncheckedExtrinsic {
				signature: None,
				function: xt.function,
			},
		}
	}

    let xt = sign::<F>(CheckedExtrinsic {
		signed: Some((alice.into(), 0)),
		function: Call::Balances(
					   BalancesCall::transfer(
						   indices::address::Address::Id(
							   bob.into(),
						   ),
						   1337
					   )
				   ),
	}, &*client);

	let mut block = client.new_block().unwrap();

	// the following push results in:
	// panicked at 'called `Result::unwrap()` on an `Err` value: ApplyExtrinsicFailed(BadSignature)'
	block.push(Decode::decode(&mut &xt.encode()[..]).unwrap()).unwrap();

	let block = block.bake().unwrap();

	let import = ImportBlock {
		origin: BlockOrigin::File,
		header: block.header().clone(),
		justification: None,
		post_digests: Vec::new(),
		body: Some(block.extrinsics().to_vec()),
		finalized: false,
		auxiliary: Vec::new(),
		fork_choice: ForkChoiceStrategy::LongestChain,
	};
	client.import_block(import, HashMap::new()).unwrap();

	Ok(())
}

/// Build a chain spec json
pub fn build_spec<G>(spec: ChainSpec<G>, raw: bool) -> error::Result<String>
	where G: RuntimeGenesis,
{
	Ok(spec.to_json(raw)?)
}
