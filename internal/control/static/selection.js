import {esc,list} from './model.js';
const split=value=>String(value||'').split(',').map(v=>v.trim()).filter(Boolean);
const tag=(id,name)=>`<span class="selected-node-tag">${esc(name)}<button type="button" data-node-remove="${esc(id)}" aria-label="Remove ${esc(name)}">×</button></span>`;
export function nodePickerHTML(name,selected,choices){
 const values=[...choices],known=new Set(values.map(v=>v.id));for(const id of list(selected))if(!known.has(id))values.push({id,name:id+' · unavailable'});
 values.sort((a,b)=>(a.name||a.id)<(b.name||b.id)?-1:(a.name||a.id)>(b.name||b.id)?1:0);
 return `<div class="node-picker" data-node-picker="${esc(name)}"><input type="hidden" name="${esc(name)}" value="${esc(list(selected).join(', '))}"><div class="node-tags">${list(selected).map(id=>tag(id,values.find(v=>v.id===id)?.name||id)).join('')}</div><details><summary>Search nodes… <span aria-hidden="true">⌄</span></summary><div class="node-picker-popup"><input type="search" data-node-search aria-label="Search nodes" placeholder="Search node name or ID">${values.map(v=>`<label data-node-option="${esc(v.id+' '+(v.name||v.id))}"><input type="checkbox" data-node-choice="${esc(v.id)}" ${selected.includes(v.id)?'checked':''}><span>${esc(v.name||v.id)}<small>${esc(v.id)}</small></span></label>`).join('')||'<p>No eligible nodes.</p>'}</div></details></div>`;
}
export function syncNodePicker(picker){
 const ids=[...picker.querySelectorAll('[data-node-choice]:checked')].map(v=>v.dataset.nodeChoice).sort();picker.querySelector('input[type=hidden]').value=ids.join(', ');
 picker.querySelector('.node-tags').innerHTML=ids.map(id=>{const label=[...picker.querySelectorAll('[data-node-option]')].find(v=>v.querySelector('[data-node-choice]').dataset.nodeChoice===id);return tag(id,label.querySelector('span').firstChild.textContent)}).join('');
}
export function pickerInput(event){
 const search=event.target.closest('[data-node-search]');if(!search)return false;
 const text=search.value.toLowerCase();for(const option of search.closest('[data-node-picker]').querySelectorAll('[data-node-option]'))option.hidden=!option.dataset.nodeOption.toLowerCase().includes(text);return true;
}
export function pickerChange(event){const choice=event.target.closest('[data-node-choice]');if(!choice)return false;syncNodePicker(choice.closest('[data-node-picker]'));return true}
export function pickerClick(event){
 const remove=event.target.closest('[data-node-remove]');if(!remove)return false;const picker=remove.closest('[data-node-picker]'),choice=[...picker.querySelectorAll('[data-node-choice]')].find(v=>v.dataset.nodeChoice===remove.dataset.nodeRemove);choice.checked=false;syncNodePicker(picker);return true;
}
