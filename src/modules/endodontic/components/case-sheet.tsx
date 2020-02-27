import { SectionComponent, TagInputComponent } from "@common-components";
import { text, user } from "@core";
import { Access, Obturation, Cleaning, EndoCase } from "@modules";
import { num } from "@utils";
import { EditableListComponent } from "common-components/editable-list/editable-list";
import { computed } from "mobx";
import { observer } from "mobx-react";
import {
	ConstrainMode,
	DetailsList,
	Dropdown,
	MessageBar,
	MessageBarType,
	SelectionMode,
	TextField
	} from "office-ui-fabric-react";
import * as React from "react";

@observer
export class EndoCaseSheetPanel extends React.Component<{
	orthoCase: EndoCase;
}> {
	@computed get canEdit() {
		return user.currentUser.canEditOrtho;
	}

	render() {
		return (
			<div>
				<SectionComponent title={text(`Features`)}>
					<Dropdown
						disabled={!this.canEdit}
						placeholder={text("Access")}
						options={Object.keys(Access).map(x => ({
							key: x,
							text: text((Access as any)[x])
						}))}
						defaultSelectedKey={this.props.orthoCase.access}
						onChange={(ev, has: any) => {
							this.props.orthoCase.access = has.key;
						}}
					/>
					<Dropdown
						disabled={!this.canEdit}
						placeholder={text("Obturbation")}
						options={Object.keys(Obturation).map(x => ({
							key: x,
							text: text((Obturation as any)[x])
						}))}
						defaultSelectedKey={this.props.orthoCase.obturation}
						onChange={(ev, has: any) => {
							this.props.orthoCase.obturation = has.key;
						}}
					/>
					<Dropdown
						disabled={!this.canEdit}
						placeholder={text("Cleaning / Shaping")}
						options={Object.keys(Cleaning).map(x => ({
							key: x,
							text: text((Cleaning as any)[x])
						}))}
						defaultSelectedKey={this.props.orthoCase.cleaning}
						onChange={(ev, has: any) => {
							this.props.orthoCase.cleaning = has.key;
						}}
					/>

					<TextField
						disabled={!this.canEdit}
						min={0}
						max={180}
						value={this.props.orthoCase.workinglength.toString()}
						onChange={(ev, v) => {
							this.props.orthoCase.workinglength = num(v!);
						}}
						type="number"
						prefix={text(`Working Length of Canals`)}
					/>

					<TextField
						disabled={!this.canEdit}
						min={0}
						max={180}
						value={this.props.orthoCase.canals.toString()}
						onChange={(ev, v) => {
							this.props.orthoCase.canals = num(v!);
						}}
						type="number"
						prefix={text(`Number of Canals`)}
					/>
				</SectionComponent>

				<SectionComponent title={text(`Problems`)}>
					<EditableListComponent
						disabled={!this.canEdit}
						label={text("Patient concerns")}
						value={this.props.orthoCase.problemsList}
						onChange={v => {
							this.props.orthoCase.problemsList = v;
							this.props.orthoCase.triggerUpdate++;
						}}
					/>
					<br />
					<br />
					<h3>{text("Other Problems")}</h3>
					{this.props.orthoCase.computedProblems.length === 0 ? (
						<MessageBar messageBarType={MessageBarType.info}>
							{text(
								"The case sheet of this patient does not show any problems that needs orthodontic treatment"
							)}
						</MessageBar>
					) : (
						<DetailsList
							constrainMode={ConstrainMode.horizontalConstrained}
							compact
							items={[
								...this.props.orthoCase.computedProblems.map(
									(x, i) => [`${i + 1}. ${x}`]
								)
							]}
							isHeaderVisible={false}
							selectionMode={SelectionMode.none}
						/>
					)}
				</SectionComponent>			
			
			</div>
		);
	}
}
