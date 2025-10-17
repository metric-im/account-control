import Component from "./Component.mjs";
import {InputText} from "./InputText.mjs";
import {InputSelect} from "./InputSelect.mjs";
import {Button} from "./Button.mjs";
import API from './API.mjs';

export default class InputACL extends Component {
    constructor(props) {
        super(props);
        this.accessLevel = ['barred','read','edit','admin']
    }
    async render(element) {
        await super.render(element);
        if (!this.props.hideTitle) {
            this.title = this.div('form-element-title');
            this.title.innerHTML = this.props.title || this.props.name;
        }
        this.tray = this.div('tray');
        this.container = this.div('container',this.tray);
        for (let item of this.props.data) {
            let elem = this.div('item',this.container);
            elem.innerHTML = item[this.props.name];
            elem.classList.add(item.level>=0?this.accessLevel[item.level]:'removed');
            elem.addEventListener('click',()=>{
                this.editTarget(item);
            })
        }
        this.control = this.div('control',this.tray);
        this.control.innerHTML = "<span class='icon icon-plus'></span>";
        this.control.addEventListener('click',async (e)=>{
            let entry = {[this.props.name]:"",level:1};
            this.props.data.push(entry);
            await this.editTarget(entry);
        });
    }
    async editTarget(data={}) {
        let editor = document.createElement('div');
        editor.classList.add('popup-form');
        let targetId = await this.draw(InputText,{name:this.props.name,title:this.props.name,data:data},editor);
        if (targetId.value) targetId.input.readOnly="readOnly";
        let level = this.new(InputSelect,{
            name:'level',data:data,title:'access level',options:[
                {name:'read',value:1},
                {name:'edit',value:2},
                {name:'admin',value:3}
            ]
        });
        await level.render(editor);
        let btnOk = this.new(Button,{title:"ok",icon:"check",onClick:async ()=>{
            data[this.props.name] = targetId.value;
            data.level = level.value;
            window.popup.close();
            await this.update();
        }});
        let btnCancel = this.new(Button,{title:"cancel",icon:"cross",onClick:()=>{
            if (this.props.data[this.props.data.length-1]==="") this.props.data.pop();
            window.popup.close();
        }});
        let btnRemove = this.new(Button,{title:"remove",icon:"trash",onClick:async ()=>{
            data.level = -1;
            window.popup.close();
            await this.update();
        }});
        await window.popup.display(this.props.name,editor,[btnOk,btnCancel,btnRemove]);
    }
    async handleUpdate(attributeName) {
        await super.handleUpdate(attributeName);
        if (attributeName === this.props.name) await this.update();
    }
    async save(entity,id) {
        await API.put(`/acl/${entity}/${id}`,this.props.data);
        await this.announceUpdate(this.props.name);
    }
}
