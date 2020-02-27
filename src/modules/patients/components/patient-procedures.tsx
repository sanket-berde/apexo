import { EditableListComponent } from "../../../common-components/editable-list/editable-list";
import { Col, getRandomTagType, Row, SectionComponent, TagInputComponent } from "@common-components";
import { text, user } from "@core";
import { Gender, Patient, patients, ProceduresDone } from "@modules";
import { num } from "@utils";
import { computed } from "mobx";
import { observer } from "mobx-react";
import { Dropdown, TextField, PrimaryButton, IconButton, IIconProps } from "office-ui-fabric-react";
import * as React from "react";
import { Procedures } from '../data';
import { generateID } from "@utils";


interface MyState {
	procedures: Procedures[];

}


interface MyProps {
	patient: Patient;
	index?: number;
}

class ProductTable extends React.Component<{
	procedures: Procedures[];
	onProductTableUpdate: (evt: any) => void;
	onRowDel: (proc: Procedures) => void;
	onRowAdd: () => void;
}> {

	render() {
		var onProductTableUpdate = this.props.onProductTableUpdate;
		var rowDel = this.props.onRowDel;
		//var filterText = this.props.filterText;
		var product = this.props.procedures.map(function (productval) {
			return (<ProductRow onProductTableUpdate={onProductTableUpdate} procedure={productval} onDelEvent={rowDel} key={productval.id} />)
		});
		return (
			<div style={{ margin: '24px 8px', display: 'flex', flexDirection: 'column' }}>
				<div style={{ margin: 'auto' }}>
					<PrimaryButton text="Add row" onClick={this.props.onRowAdd} className="btn btn-success pull-right" />
				</div>
				<div style={{ height: '100%', minHeight: 100, marginTop: 16 }}>
					<table className="table table-bordered">
						<thead>
							<tr>
								<th>Done</th>
								<th>Date</th>
								<th>Priority</th>
								<th>Tooth</th>
								<th>Description</th>
								<th>Fees</th>
								<th>Discount</th>
								<th>Fees Discount</th>
								<th>Insurance</th>
								<th>Patient Signature</th>
							</tr>
						</thead>

						<tbody>
							{product}

						</tbody>

					</table>
				</div>

			</div>
		);

	}

}

class ProductRow extends React.Component<{
	procedure: Procedures;
	onProductTableUpdate: (evt: any) => void;
	onDelEvent: (proc: Procedures) => void;
}> {
	onDelEvent() {
		this.props.onDelEvent(this.props.procedure);
	}
	trashIcon: IIconProps = { iconName: 'Trash' };
	render() {
		return (
			<tr className="eachRow">
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "done",
					value: this.props.procedure.done,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "date",
					value: this.props.procedure.date,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "priority",
					value: this.props.procedure.priority,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "tooth",
					value: this.props.procedure.tooth,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "desc",
					value: this.props.procedure.desc,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "fees",
					value: this.props.procedure.fees,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "discount",
					value: this.props.procedure.discount,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "fdiscount",
					value: this.props.procedure.fdiscount,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "insurance",
					value: this.props.procedure.insurance,
					id: this.props.procedure.id
				}} />
				<EditableCell onProductTableUpdate={this.props.onProductTableUpdate} cellData={{
					"type": "psignature",
					value: this.props.procedure.psignature,
					id: this.props.procedure.id
				}} />
				<td className="del-cell">
					<IconButton className="delete-btn" iconProps={this.trashIcon} title="Delete row" onClick={this.onDelEvent.bind(this)} style={{ border: '1px solid red', height: 22 }} />
				</td>
			</tr>
		);

	}

}
class EditableCell extends React.Component<{
	onProductTableUpdate: (evt: any) => void;
	cellData: any;
}> {

	render() {
		return (
			<td style={{ width: '10%' }}>
				<input style={{ width: '100%' }} type='text' name={this.props.cellData.type} id={this.props.cellData.id} value={this.props.cellData.value} onChange={this.props.onProductTableUpdate} />
			</td>
		);

	}
}

@observer
export class PatientProcedures extends React.Component<MyProps, MyState>
{
	constructor(props: MyProps) {
		super(props);
		this.state = {
			procedures: this.props.patient.procedures
		};
	}
	handleRowDel = (prod: Procedures): void => {
		var index = this.state.procedures.indexOf(prod);
		this.state.procedures.splice(index, 1);
		//	this.setState( { procedures: this.state.procedures } );
		this.setState({
			procedures: this.state.procedures
		}, () => {
			this.props.patient.procedures = this.state.procedures
		})
	};

	handleAddEvent = (): void => {
		var d = new Date();
		let date = [
			d.getFullYear(),
			('0' + (d.getMonth() + 1)).slice(-2),
			('0' + d.getDate()).slice(-2)
		].join('-');
		let idx = generateID();
		var product = {
			id: "",
													name: "",
													quantity: 0,
													patientID: "",
													tooth: [],
													fees:0 ,
													done: false,
													date: new Date().toISOString()
		}

		var pp = new Procedures(product);
		//product.SetPatientID(this.props.patient._id);
		this.state.procedures.push(pp);
		//this.setState({ procedures: this.state.procedures });	
		this.setState({
			procedures: this.state.procedures
		}, () => {
			this.props.patient.procedures = this.state.procedures
		})
	}

	handleProductTable = (evt: any): void => {
		var item = {
			id: evt.target.id,
			name: evt.target.name,
			value: evt.target.value
		};
		var products = this.state.procedures.slice();
		var newProducts = products.map(function (product: any) {

			for (var key in product) {
				if (key == item.name && product.id == item.id) {
					product[key] = item.value;

				}
			}
			return product;
		});

		this.setState({
			procedures: newProducts
		}, () => {
			this.props.patient.procedures = this.state.procedures
		})
		//  console.log(this.state.products);

	}

	render() {
		return (

			<div>
				<ProductTable onProductTableUpdate={this.handleProductTable.bind(this)} onRowAdd={this.handleAddEvent.bind(this)} onRowDel={this.handleRowDel.bind(this)} procedures={this.state.procedures} />
			</div>

		);
	}
}
