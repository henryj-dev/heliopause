#!/usr/bin/env node
/** Explicit inventory-to-execution-ledger migration. Never removes a fence or an old lock. */
import { installCliLanguage } from '../src/operator-i18n.ts';
import { parseArgs } from 'node:util';
import { NetworkRegistryStore } from '../src/network-registry.ts';
installCliLanguage();
const {values}=parseArgs({options:{registry:{type:'string'}}});
if(!values.registry) throw new Error('--registry is required');
const store=new NetworkRegistryStore(values.registry);
store.initializeExecutions();
console.log(JSON.stringify({initialized:true,revision:store.read().revision}));
