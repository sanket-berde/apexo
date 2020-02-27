import { observable } from "mobx";
import { observer } from "mobx-react";
import { IconButton } from "office-ui-fabric-react";
import * as React from "react";

@observer
export class SectionComponent extends React.Component<{
	title: string;
	zIndex?: number;
	backgroundColor?: string;
}> {
	@observable show: boolean = true;
	render() {
		return (
			<section
				className="cl-section"
				style={{ zIndex: this.props.zIndex, backgroundColor: this.props.backgroundColor, position: 'relative' }}
			>
				<div style={{position: 'absolute', top: 0, left: 0, width: '100%', height: 35, backgroundColor: '#f3f3f3', borderBottom: '1px solid #e3e3e3', zIndex: 1}}></div>
				<IconButton
					style={{zIndex: 11}}
					className="chevron"
					iconProps={{
						iconName: this.show ? "chevronUp" : "chevronDown"
					}}
					onClick={() => {
						this.show = !this.show;
					}}
				/>
				<h3
					className={
						"cl-section-title" + (this.show ? "" : " only-title")
					}
					onClick={() => {
						this.show = !this.show;
					}}
					style={{position: 'absolute', top: 0, left: 0, zIndex: 10,  padding: '6px 16px', borderBottom: 'none'}}
				>
					{this.props.title}
				</h3>
				<div style={{marginTop: this.show ? 40 : 0}}>
					{this.show ? this.props.children : ""}
				</div>
				
			</section>
		);
	}
}
