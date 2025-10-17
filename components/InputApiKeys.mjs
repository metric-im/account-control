import Component from './Component.mjs';
import InputInlineTable from './InputInlineTable.mjs';
import IdForge from './IdForge.mjs';

export default class InputApiKeys extends Component {
  constructor(props) {
    super(props);
  }
  async render(element) {
    await super.render(element);
    this.table = await this.draw(InputInlineTable,{
      name:this.props.name,
      data:this.props.data,
      cols:[
        {name:'key',title:'Api Key',component:KeyField},
        {name:'domain',title:'Allowed Domain(s)'},
        {name:'comment',title:'Comment'}
      ]
    },this.element);
  }
}

class KeyField extends Component {
  constructor(props) {
    super(props);
    this.key = IdForge.randomId(32);
  }
  async render(element) {
    await super.render(element);
    this.element.innerHTML = this.key;
  }
  get value() {
    return this.key;
  }
  set value(val) {
  }
}
