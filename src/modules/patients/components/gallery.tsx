import { fileTypes, PickAndUploadComponent, SectionComponent } from "@common-components";
import { files, GALLERIES_DIR, status, text, user } from "@core";
import { Patient, setting } from "@modules";
import { diff } from "fast-array-diff";
import { computed, observable, observe } from "mobx";
import { observer } from "mobx-react";
import { Icon, IconButton, MessageBar, MessageBarType, TooltipHost } from "office-ui-fabric-react";
import { Slider } from 'office-ui-fabric-react/lib/Slider';
import * as React from "react";
// import {
// 	Magnifier,
// 	MOUSE_ACTIVATION,
// 	TOUCH_ACTIVATION,
//   } from "react-image-magnifiers";
// @ts-ignore
import PinchZoomPan from "react-responsive-pinch-zoom-pan";

export interface ISliderBasicExampleState {
	value: number;
	zoom: number;
	startPosX: number;
	startPosY: number;
	endPosX: number;
	endPosY: number;
}


@observer
export class PatientGalleryPanel extends React.Component<
	{ patient: Patient },
	{}
> {



	@computed get canEdit() {
		// return user.currentUser.canEditPatients;
		return true;
	}

	@observable uploading: boolean = false;

	@observable selectedImagePath: string = "";

	@observable imagesTable: { [key: string]: string } = {};

	@computed get selectedImageURI() {
		return this.imagesTable[this.selectedImagePath];
	}

	stopObservation: () => void = function() {};

	public state: ISliderBasicExampleState = { 
		value: 0, 
		zoom: 1, 
		startPosX: 0, 
		startPosY: 0, 
		endPosX: 0, 
		endPosY: 0,
	};

	render() {
		//console.log('status: ', status);
		// const { endPosX: x2, endPosY: y2, startPosX: x1, startPosY: y1, zoom } = this.state;
		// let bgWidth = 430;

		// let movePercentage = {
		// 	x: 100 * (x2 - x1) / bgWidth,
		// 	y: 100 * (y2 - y1) / bgWidth,
		// };

		// let actualMovePercentage = {
		// 	// x: 0.7 / (1 - zoom / 100) * movePercentage.x,
		// 	// y: 0.7 / (1 - zoom / 100) * movePercentage.y,
		// 	x: movePercentage.x,
		// 	y: movePercentage.y,
		// };

		//console.log(actualMovePercentage);

		return (
			<SectionComponent title={text(`Patient Gallery`)}>
				{status.online || true ? (
					status.dropboxActive ? (
						<div className="spg-p">
							{this.props.patient.gallery.length === 0 ? (
								<MessageBar
									messageBarType={MessageBarType.info}
								>
									{text(
										"This patient does not seem to have any photo record uploaded, press the plus sign button below to start uploading"
									)}
								</MessageBar>
							) : (
								""
							)}
							<br />
							<div className="thumbs">
								{this.canEdit ? (
									this.uploading ? (
										<Icon
											iconName="sync"
											className="rotate"
											style={{ padding: 10 }}
										/>
									) : (
										<PickAndUploadComponent
											allowMultiple={true}
											accept={fileTypes.image}
											onFinish={paths => {
												//console.log(paths);
												this.props.patient.gallery.push(
													...paths
												);
												paths.forEach(async path => {
													await this.addImage(path);
												})
											}}
											onStartLoading={() => {
												this.uploading = true;
											}}
											onFinishLoading={() => {
												this.uploading = false;
											}}
											targetDir={`${GALLERIES_DIR}/${
												this.props.patient._id
											}`}
										>
											<TooltipHost
												content={text("Add photo")}
											>
												<IconButton
													className={`add-photo`}
													iconProps={{
														iconName: "Photo2Add"
													}}
												/>
											</TooltipHost>
										</PickAndUploadComponent>
									)
								) : (
									""
								)}
								{Object.keys(this.imagesTable).map(
									imagePath => {
										const URI = this.imagesTable[imagePath];
										return URI ? (
											<span
												className={`thumb ${
													this.selectedImagePath ===
													imagePath
														? "selected"
														: ""
												}`}
												key={imagePath}
												style={{
													backgroundImage: `url('${
														URI ? URI : ""
													}')`,
													filter: 'grayscale(95%)'
												}}
												onClick={() => {
													this.selectedImagePath = imagePath;
												}}
											/>
										) : (
											<div
												key={imagePath + "-placeholder"}
												className="placeholder"
											>
												<Icon
													iconName="sync"
													className="rotate"
												/>
											</div>
										);
									}
								)}
							</div>
							
								<div className="viewport" 
								 //onMouseDown={e => this.setState({startPosX: e.clientX, startPosY: e.clientY})}
								 //onMouseUp={e => this.setState({endPosX: 0, endPosY: 0, startPosX: 0, startPosY: 0})}
								 //onMouseMove={e => {
									 //if(this.state.startPosX > 0 || this.state.startPosY > 0){
										//this.setState({endPosX:  e.pageX, endPosY: e.pageY})
									 //}
								 //}}
								 style={{
									 height: 300,
									 width: 430,
									//  backgroundImage: `url(${this.selectedImageURI})`,
									//  //backgroundPosition: `${50 - actualMovePercentage.x}% ${50 - actualMovePercentage.y}%`,
									//  backgroundPosition: `${215 - actualMovePercentage.x}% ${150 - actualMovePercentage.y}%`,
									//  backgroundSize: this.state.zoom > 0 ? `calc(430px + (430px * ${this.state.zoom}/100)) calc(300px + (300px * ${this.state.zoom}/100))` : 'cover',
									//  filter: `grayscale(${this.state.value}%)`,
									//  cursor: this.state.zoom > 0 ? 'move' : 'default',
									//  backgroundRepeat: 'no-repeat',
								 }}
								 >
									 {this.selectedImagePath ? (
										 <>
										<IconButton
											className="delete-photo"
											iconProps={{ iconName: "trash" }}
											onClick={async () => {
												await this.removeImage(
													this.selectedImagePath
												);
												this.selectedImagePath = "";
											}}
										/>

										{/* <Magnifier
											imageSrc={`${this.selectedImageURI}`}
											imageAlt="Example"
											mouseActivation={MOUSE_ACTIVATION.DOUBLE_CLICK}
											largeImageSrc={this.state.image}
										/> */}

<PinchZoomPan maxScale={100} scale={this.state.zoom} zoomButtons={false} filterValue={this.state.value}
// style={{
// 					filter: `grayscale(${this.state.value}%)`,
// 					cursor: this.state.zoom > 0 ? 'move' : 'default',
// 				}}
				>
				<img alt='image' src={`${this.selectedImageURI}`}  />
</PinchZoomPan>

										{/* <MagnifierContainer>
										<div className="example-class">
											<MagnifierPreview imageSrc="./image.jpg" />
										</div>
											<MagnifierZoom style={{ height: "400px" }} imageSrc="./image.jpg">
										</MagnifierContainer> */}
										</>
				
									) : (
								""
							)}
								</div>
							
						</div>
					) : (
						<MessageBar messageBarType={MessageBarType.warning}>
							{text(
								"A valid DropBox access token is required for this section"
							)}
						</MessageBar>
					)
				) : (
					<MessageBar messageBarType={MessageBarType.warning}>
						{text(
							"You can not access patient gallery while offline"
						)}
					</MessageBar>
				)}
				<div style={{ clear: "both" }} />
				<div style={{padding: '32px 16px 8px 16px'}}>
					<div>
						<Slider
							label="Grayscale"
							max={100}
							ariaValueText={(value: number) => `${value} percent`}
							valueFormat={(value: number) => `${value}%`}
							showValue={true}
							onChange={(value: number) => this.setState({value}) }
						/>
					</div>
					<div>
						<Slider
							label="Zoom"
							max={100}
							ariaValueText={(value: number) => `${value} percent`}
							valueFormat={(value: number) => `${value}%`}
							showValue={true}
							onChange={(zoom: number) => {
								this.setState({zoom});
								//this.viewport.current.style.transform = `scale(430 + (430 * ${this.state.zoom}/100), 300 + (300 * ${this.state.zoom}/100))`;
							} }
						/>
					</div>
				</div>
				
			</SectionComponent>
		);
	}

	componentDidMount() {
		this.props.patient.gallery.forEach(async path => {
			await this.addImage(path);
		});
		this.stopObservation = this.observe();
		
		// 		const el = this.viewport.current;
		// if(el){
		// 	el.addEventListener('mousemove', (e) => {
		// 		el.style.backgroundPositionX = -e.offsetX + "px";
		// 		el.style.backgroundPositionY = -e.offsetY + "px";
		// 	});
		// }
	}

	componentWillUnmount() {
		this.stopObservation();
	}

	async addImage(path: string) {
		this.imagesTable[path] = "";
		const uri = await files.get(path);
		this.imagesTable[path] = uri;
		return;
	}

	async removeImage(path: string) {
		await files.remove(this.selectedImagePath);
		const selectedImageIndex = this.props.patient.gallery.indexOf(
			this.selectedImagePath
		);
		this.props.patient.gallery.splice(selectedImageIndex, 1);
		delete this.imagesTable[path];
		return;
	}

	observe() {
		return observe(this.props.patient, change => {
			if (change.name === "gallery") {
				const diffResult = diff(
					Object.keys(this.imagesTable),
					this.props.patient.gallery
				);
				diffResult.added.forEach(path => {
					this.addImage(path);
				});
				diffResult.removed.forEach(path => {
					this.removeImage(path);
				});
			}
		});
	}
}
