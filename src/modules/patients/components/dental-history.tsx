import "rc-collapse/assets/index.css";
import {
  AsyncComponent,
  Col,
  ProfileComponent,
  Row,
  SectionComponent
} from "@common-components";
import { text, user } from "@core";
import {
  conditionToColor,
  Patient,
  ToothCondition,
  Diagnosis,
  procedures,
  procedureList
} from "@modules";
import { EditableListComponent } from "common-components/editable-list/editable-list";
import { computed, observable, values } from "mobx";
import { observer } from "mobx-react";
import {
  Dropdown,
  IconButton,
  Panel,
  PanelType,
  Toggle
} from "office-ui-fabric-react";
import * as React from "react";
import Select from "react-dropdown-select";
import Collapse, { Panel as CustomePanel } from "rc-collapse";
import { Row as BTRow, Col as BTCol } from "react-bootstrap";
import { Procedures } from "../data";
import { max } from "date-fns";

interface MyProps {
  patient: Patient;
  toggleProcedureTable: () => void;
}

interface MyState {
  printview: string;
  showDiagnosis: boolean;
  showProcedure: boolean;
  activeKey: any[];
  accordion: boolean;
  currentProcedureIndex: number;
  selectedProcedure: any;
  selectedTeeth: number[];
  saveProcedureSeparate: boolean;
  searchProcedureText: string;
}

//function createRef<T>(): RefObject<T>

@observer
export class DentalHistoryPanel extends React.Component<
  { patient: Patient; toggleProcedureTable: () => void },
  MyState
> {
  constructor(props: MyProps) {
    super(props);
    this.state = {
      printview: "",
      showDiagnosis: false,
      showProcedure: false,
      activeKey: [],
      accordion: false,
      currentProcedureIndex: 0,
      selectedProcedure: {},
      selectedTeeth: [],
      saveProcedureSeparate: true,
      searchProcedureText: ""
    };
  }

  @observable viewChart: boolean = true;
  @observable viewToothISO: number = 0;
  @observable triggerUpdate: number = 0;

  @computed get canEdit() {
    return user.currentUser.canEditPatients;
  }

  onChange = (activeKey: any) => {
    this.setState({
      activeKey
    });
  };

  componentWillMount() {
    this.viewToothISO = 0;
  }
  render() {
    console.log("this.props.patient", this.props.patient.procedureGraphicCode);
    let options = { left: "left", right: "right", both: "both" };
    const procedureShown = this.state.searchProcedureText
      ? procedureList.filter(pro =>
          pro.value
            .toUpperCase()
            .includes(this.state.searchProcedureText.toUpperCase())
        )
      : procedureList.filter(
          (pro: any) => pro.parentIndex === this.state.currentProcedureIndex + 1
        );
    return (
      <div className="dental-history teeth">
        <Toggle
          defaultChecked={true}
          onText={text("View graphic chart")}
          offText={text("View sorted table")}
          onChange={(ev, newVal) => {
            this.viewChart = newVal!;
          }}
        />

        <Dropdown
          disabled={!this.canEdit}
          placeholder={text("Print")}
          options={Object.keys(options).map(x => ({
            key: x,
            text: text((options as any)[x])
          }))}
          defaultSelectedKey={options.both}
          onChange={(ev, has: any) => {
            if (has.key === options.left) {
              this.setState(
                {
                  printview: "left"
                },
                () => {
                  window.print();
                }
              );
            }
          }}
        />
        {/*	<ReactToPrint
							trigger={() => <IconButton
								iconProps={{ iconName: "print" }}
							
							/>}
							content={() => this}
							/> */}

        <div className="m-t-20">
          {this.viewChart ? (
            <div className="chart">
              <SectionComponent
                title={text(`Permanent Teeth`)}
                backgroundColor="#F7F7F7"
              >
                <AsyncComponent
                  key="teeth-permanent"
                  loader={async () => {
                    const Component = (await import("./teeth-permanent"))
                      .TeethPermanentChart;
                    return (
                      <Component
                        teeth={this.props.patient.teeth}
                        patient={this.props.patient}
                        onClick={number => {
                          this.viewToothISO = number;
                          if (this.state.selectedTeeth.indexOf(number) === -1) {
                            this.state.selectedTeeth.push(number);
                            this.setState({ ...this.state });
                          } else {
                            const selectedTeeth = this.state.selectedTeeth;
                            selectedTeeth.splice(
                              selectedTeeth.indexOf(number),
                              1
                            );
                            this.setState({ selectedTeeth });
                          }
                        }}
                      />
                    );
                  }}
                />
              </SectionComponent>
              <SectionComponent
                title={text(`Deciduous Teeth`)}
                backgroundColor="#F7F7F7"
              >
                <AsyncComponent
                  key="teeth-primary"
                  loader={async () => {
                    const Component = (await import("./teeth-deciduous"))
                      .TeethDeciduousChart;
                    return (
                      <Component
                        teeth={this.props.patient.teeth}
                        patient={this.props.patient}
                        onClick={number => {
                          this.viewToothISO = number;
                          if (this.state.selectedTeeth.indexOf(number) === -1) {
                            this.state.selectedTeeth.push(number);
                            this.setState({ ...this.state });
                          } else {
                            const selectedTeeth = this.state.selectedTeeth;
                            selectedTeeth.splice(
                              selectedTeeth.indexOf(number),
                              1
                            );
                            this.setState({ selectedTeeth });
                          }
                        }}
                      />
                    );
                  }}
                />
              </SectionComponent>
            </div>
          ) : (
            <div className="tabulated">
              <SectionComponent title={text(`Permanent Teeth`)}>
                <table className="permanent">
                  <tbody>
                    <tr>
                      {[
                        this.mapQuadrant(11, 18, true),
                        this.mapQuadrant(21, 28, false)
                      ]}
                    </tr>
                    <tr>
                      {[
                        this.mapQuadrant(41, 48, true),
                        this.mapQuadrant(31, 38, false)
                      ]}
                    </tr>
                  </tbody>
                </table>
              </SectionComponent>
              <SectionComponent title={text(`Deciduous Teeth`)}>
                <table className="deciduous">
                  <tbody>
                    <tr>
                      {[
                        this.mapQuadrant(51, 55, true),
                        this.mapQuadrant(61, 65, false)
                      ]}
                    </tr>
                    <tr>
                      {[
                        this.mapQuadrant(81, 85, true),
                        this.mapQuadrant(71, 75, false)
                      ]}
                    </tr>
                  </tbody>
                </table>
              </SectionComponent>
            </div>
          )}
        </div>

        <Panel
          isOpen={
            !!this.props.patient.teeth[this.viewToothISO] &&
            !this.state.showProcedure
          }
          type={PanelType.smallFixedFar}
          closeButtonAriaLabel="Close"
          isLightDismiss={true}
          onDismiss={() => {
            this.viewToothISO = 0;
            this.setState({
              ...this.state,
              showDiagnosis: false
            });
          }}
          onRenderNavigation={() => {
            const tooth = this.props.patient.teeth[this.viewToothISO];

            return (
              <Row className="panel-heading">
                <Col span={22}>
                  <ProfileComponent
                    name={`ISO: ${tooth ? tooth.ISO : ""} - Universal: ${
                      tooth ? tooth.Universal : ""
                    }`}
                    secondaryElement={
                      <span>
                        {tooth
                          ? tooth.Name.split(" ")
                              .filter((x, i) => i)
                              .join(" ")
                          : ""}
                      </span>
                    }
                    onRenderInitials={() => (
                      <span className="palmer">
                        {tooth ? tooth.Palmer : ""}
                      </span>
                    )}
                    size={3}
                  />
                </Col>
                <Col span={2} className="close">
                  <IconButton
                    iconProps={{ iconName: "cancel" }}
                    onClick={() => {
                      this.viewToothISO = 0;
                    }}
                  />
                </Col>
              </Row>
            );
          }}
        >
          <br />
          <br />
          {this.props.patient.teeth[this.viewToothISO] ? (
            <div>
              <div className="tooth-details">
                <Dropdown
                  placeholder={text(`Condition`)}
                  onChange={(ev, newVal: any) => {
                    this.props.patient.teeth[
                      this.viewToothISO
                    ].condition = newVal.key.toString();
                    this.props.patient.triggerUpdate++;
                    this.forceUpdate();
                  }}
                  defaultSelectedKey={
                    this.props.patient.teeth[this.viewToothISO].condition
                  }
                  className="single-tooth-condition"
                  options={Object.keys(ToothCondition).map(c => ({
                    key: c,
                    text: text(c)
                  }))}
                  disabled={!this.canEdit}
                />
                <EditableListComponent
                  label={text("History notes")}
                  value={this.props.patient.teeth[this.viewToothISO].notes}
                  disabled={!this.canEdit}
                  onChange={e => {
                    this.props.patient.teeth[this.viewToothISO].notes = e;
                    this.props.patient.triggerUpdate++;
                  }}
                />
              </div>
              <div className="add-diagnosis-wrapper">
                <div
                  className="normal-title"
                  onClick={() => {
                    this.props.patient.procedureGraphicCode = [];
                    this.props.patient.teeth[this.viewToothISO].diagnosis = {
                      id: "",
                      value: "",
                      date: new Date()
                    };
                    const procedures = this.props.patient.procedures.filter(
                      pro => !pro.tooth.includes(this.viewToothISO)
                    );
                    this.props.patient.procedures = procedures;
                    this.viewToothISO = 0;
                    this.setState({ ...this.state, showDiagnosis: false });
                  }}
                >
                  Normal
                </div>
                <div
                  className="add-diagnosis-title"
                  onClick={() => {
                    this.setState({ ...this.state, showDiagnosis: true });
                  }}
                >
                  Add diagnosis
                </div>
                <div
                  className="add-diagnosis-title"
                  onClick={() =>
                    this.setState({ ...this.state, showProcedure: true })
                  }
                >
                  Add Procedure
                </div>

                {(this.state.showDiagnosis ||
                  (this.props.patient.teeth[this.viewToothISO].diagnosis &&
                    this.props.patient.teeth[this.viewToothISO].diagnosis
                      .id)) && (
                  <React.Fragment>
                    <p style={{ marginBottom: "5px" }}>Filter by name</p>
                    <Select
                      options={Object.keys(Diagnosis).map(c => ({
                        id: c,
                        key: c,
                        value: text(Diagnosis[c]),
                        title: Diagnosis[c].title
                      }))}
                      searchable={true}
                      searchBy="title"
                      itemRenderer={({
                        item,
                        methods
                      }: {
                        item: any;
                        methods: any;
                      }) => (
                        <Collapse
                          accordion={this.state.accordion}
                          onChange={this.onChange}
                          activeKey={this.state.activeKey}
                        >
                          <CustomePanel
                            style={{
                              padding: "10px",
                              backgroundColor: "#ffffff",
                              borderTop: "none"
                            }}
                            key={item.id}
                            header={item.value.title}
                          >
                            {item.value.diagnosis.map(
                              (d: any, index: number) => (
                                <p
                                  style={{
                                    paddingLeft: "10px",
                                    color: "#0078d4"
                                  }}
                                  key={d.id + index}
                                  onClick={() => {
                                    this.props.patient.teeth[
                                      this.viewToothISO
                                    ].diagnosis = {
                                      id: d.id,
                                      value: d.value,
                                      date: new Date()
                                    };
                                    this.props.patient.triggerUpdate++;
                                    this.forceUpdate();
                                    // methods.addItem(item)
                                  }}
                                >{`${d.id} ${d.value}`}</p>
                              )
                            )}
                          </CustomePanel>
                        </Collapse>
                      )}
                    />
                  </React.Fragment>
                )}
                {this.props.patient.teeth[this.viewToothISO].diagnosis &&
                  this.props.patient.teeth[this.viewToothISO].diagnosis.id && (
                    <p>
                      Selected diagnosis:{" "}
                      {
                        this.props.patient.teeth[this.viewToothISO].diagnosis
                          .value
                      }
                    </p>
                  )}
              </div>
            </div>
          ) : (
            ""
          )}
        </Panel>

        {this.state.showProcedure && (
          <div
            style={{
              zIndex: 12,
              borderTop: "1px solid #999",
              marginTop: "5px",
              position: "fixed",
              bottom: 0,
              left: 0,
              right: 0,
              padding: "10px 40px",
              backgroundColor: "#ffffff",
              maxHeight: "300px",
              overflow: "scroll"
            }}
          >
            <BTRow className="flex-row-reverse">
              <BTCol>
                <p
                  style={{
                    textAlign: "right",
                    color: "#2d89ef",
                    cursor: "pointer",
                    marginBottom: "0"
                  }}
                  onClick={() => this.setState({ showProcedure: false })}
                >
                  Close
                </p>
              </BTCol>
            </BTRow>
            <BTRow>
              <BTCol xs={4}>
                <p style={{ fontWeight: "bold", marginBottom: "5px" }}>
                  Status
                </p>
              </BTCol>
              <BTCol xs={8}>
                <p style={{ fontWeight: "bold", marginBottom: "5px" }}>Teeth</p>
              </BTCol>
            </BTRow>
            <BTRow>
              <BTCol xs={4}>
                <div style={{ display: "flex" }}>
                  <p style={{ marginRight: "10px" }}>Planned</p>
                  <p>Completed</p>
                </div>
              </BTCol>
              <BTCol xs={3}>
                {this.state.selectedTeeth &&
                  this.state.selectedTeeth.length > 0 && (
                    <p>
                      {this.state.selectedTeeth.map(teethNo => {
                        return `#${teethNo} `;
                      })}
                    </p>
                  )}
              </BTCol>
            </BTRow>

            {procedures[this.state.currentProcedureIndex] &&
            procedures[this.state.currentProcedureIndex].children ? (
              <BTRow style={{ width: "400px" }}>
                {procedures[this.state.currentProcedureIndex].children.map(
                  child => {
                    let className = "sub-procedure";
                    if (
                      this.props.patient.procedureGraphicCode &&
                      this.props.patient.procedureGraphicCode.length > 0
                    ) {
                      this.props.patient.procedureGraphicCode.map(code => {
                        if (code.includes(child)) {
                          className += " sub-procedure-selected";
                        }
                      });
                    }
                    return (
                      <BTCol>
                        <p
                          className={className}
                          onClick={() => {
                            if (
                              this.state.selectedTeeth &&
                              this.state.selectedTeeth.length > 0
                            ) {
                              this.state.selectedTeeth.map(tooth => {
                                const procedureGraphicCode = this.props.patient
                                  .procedureGraphicCode;
                                let graphicCode =
                                  procedures[this.state.currentProcedureIndex]
                                    .id +
                                  child +
                                  tooth;
                                const indexOfGraphicCode = this.props.patient.procedureGraphicCode.indexOf(
                                  graphicCode
                                );
                                if (indexOfGraphicCode === -1) {
                                  procedureGraphicCode.push(graphicCode);
                                } else {
                                  procedureGraphicCode.splice(
                                    indexOfGraphicCode,
                                    1
                                  );
                                }
                                this.props.patient.procedureGraphicCode = procedureGraphicCode;
                              });
                            }
                          }}
                        >
                          {child}
                        </p>
                      </BTCol>
                    );
                  }
                )}
              </BTRow>
            ) : null}
            <BTRow className="m-2">
              <BTCol>
                <input
                  className="w-100 p-1"
                  type="text"
                  placeholder="Search... "
                  value={this.state.searchProcedureText}
                  onChange={e => {
                    this.setState({ searchProcedureText: e.target.value });
                  }}
                />
              </BTCol>
            </BTRow>
            <BTRow className="justify-content-xs-between">
              {procedures.map((pro: any, index: number) => (
                <BTCol
                  key={index}
                  style={{ cursor: "pointer" }}
                  className="d-flex flex-column align-items-xs-centre"
                  onClick={() => {
                    if (
                      !procedures[index].children ||
                      ["rootCanal", "prosthetics"].includes(
                        procedures[index].id
                      )
                    ) {
                      if (
                        this.state.selectedTeeth &&
                        this.state.selectedTeeth.length > 0
                      ) {
                        this.state.selectedTeeth.map(tooth => {
                          const procedureGraphicCode = this.props.patient
                            .procedureGraphicCode;
                          let graphicCode = pro.id + "" + tooth;
                          const indexOfGraphicCode = this.props.patient.procedureGraphicCode.indexOf(
                            graphicCode
                          );
                          if (indexOfGraphicCode === -1) {
                            procedureGraphicCode.push(graphicCode);
                          }
                          // This is another flow that show  procedure together
                          // else {
                          //   procedureGraphicCode.splice(indexOfGraphicCode, 1);
                          // }

                          // This is another flow that show one procedure at the time
                          if (
                            !procedures[this.state.currentProcedureIndex]
                              .children ||
                            ["rootCanal", "prosthetics"].includes(
                              procedures[this.state.currentProcedureIndex].id
                            )
                          ) {
                            let preGraphicCode =
                              procedures[this.state.currentProcedureIndex].id +
                              "" +
                              tooth;
                            const indexOfPreGraphicCode = this.props.patient.procedureGraphicCode.indexOf(
                              preGraphicCode
                            );
                            if (indexOfPreGraphicCode !== -1) {
                              procedureGraphicCode.splice(
                                indexOfPreGraphicCode,
                                1
                              );
                            }
                          }
                          this.props.patient.procedureGraphicCode = procedureGraphicCode;
                        });
                      }
                    }
                    this.setState({ currentProcedureIndex: index });
                  }}
                >
                  <div style={{ margin: "0 auto" }}>
                    <img src={`./icons/${pro.id}.png`} />
                  </div>
                  <p
                    style={
                      index === this.state.currentProcedureIndex
                        ? {
                            marginTop: "10px",
                            textAlign: "center",
                            color: "#2d89ef"
                          }
                        : { marginTop: "10px", textAlign: "center" }
                    }
                  >
                    {pro.title}
                  </p>
                </BTCol>
              ))}
            </BTRow>
            <div
              style={{
                height: "300px",
                padding: "10px 20px",
                overflow: "auto",
                backgroundColor: "#F7F7F7"
              }}
            >
              {procedureShown.map(procedure => {
                let procedureInSelectedList = this.state.selectedProcedure[
                  `${procedure.parentId}-${procedure.parentIndex}${procedure.order}`
                ];
                return (
                  <BTRow
                    className="justify-content-between"
                    style={{ padding: "5px" }}
                  >
                    {/* index +1 cuz in procedurelist id start from 1 but procedures array start index from 0 */}
                    <BTCol
                      style={{ cursor: "pointer" }}
                      xs={8}
                      onClick={() => {
                        if (procedureInSelectedList) {
                          const selectedProcedure = this.state
                            .selectedProcedure;
                          delete this.state.selectedProcedure[
                            `${procedure.parentId}-${procedure.parentIndex}${procedure.order}`
                          ];
                          this.setState({ selectedProcedure });
                        } else {
                          const selectedProcedure = {
                            ...this.state.selectedProcedure
                          };
                          selectedProcedure[
                            `${procedure.parentId}-${procedure.parentIndex}${procedure.order}`
                          ] = { ...procedure, quantity: 1 };
                          this.setState({ selectedProcedure });
                        }
                      }}
                    >
                      <p style={{ marginBottom: "5px" }}>
                        {procedure.parentIndex}({procedure.order})
                      </p>
                      <p style={{ margin: 0 }}>{procedure.value}</p>
                    </BTCol>
                    <BTCol xs={1}>
                      {procedureInSelectedList && (
                        <div className="d-flex">
                          <input
                            style={{
                              borderRadius: "5px",
                              padding: "10px",
                              border: "none",
                              width: "60px"
                            }}
                            type="number"
                            value={procedureInSelectedList.quantity}
                            onChange={e => {
                              procedureInSelectedList.quantity = e.target.value;
                              this.setState({ ...this.state });
                            }}
                          />
                        </div>
                      )}
                    </BTCol>
                    <BTCol xs={2}>
                      <div className="d-flex">
                        <input
                          style={{
                            borderRadius: "5px",
                            padding: "10px 5px",
                            border: "none"
                          }}
                          type="number"
                          value={
                            procedureInSelectedList &&
                            procedureInSelectedList.price !== undefined
                              ? procedureInSelectedList.price
                              : procedure.defaultPrice
                          }
                          onChange={e => {
                            if (procedureInSelectedList) {
                              procedureInSelectedList.price = e.target.value;
                              this.setState({ ...this.state });
                            } else {
                              alert(
                                "Please select the procedure before modifying its price"
                              );
                            }
                          }}
                        />
                        <div
                          style={{
                            textAlign: "center",
                            padding: "10px 10px",
                            backgroundColor: "#ffffff",
                            color: "#2d89ef"
                          }}
                        >
                          $
                        </div>
                      </div>
                    </BTCol>
                  </BTRow>
                );
              })}
            </div>
            <BTRow className="justify-content-between mt-3 align-items-centre">
              <BTCol xs={9}>
                {this.state.selectedTeeth &&
                  this.state.selectedTeeth.length > 0 && (
                    <div className="form-check">
                      <input
                        className="form-check-input"
                        id="checkForTooth"
                        type="checkbox"
                        checked={this.state.saveProcedureSeparate}
                        onChange={e =>
                          this.setState({
                            saveProcedureSeparate: e.target.checked
                          })
                        }
                      />
                      <label
                        className="form-check-label"
                        htmlFor="checkForTooth"
                      >
                        {" "}
                        Save these procedures for each tooth separately{" "}
                      </label>
                    </div>
                  )}
              </BTCol>
              <BTCol xs={3}>
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    const procedures: Procedures[] = [];

                    if (
                      this.state.selectedProcedure &&
                      Object.keys(this.state.selectedProcedure).length > 0
                    ) {
                      for (let [key] of Object.entries(
                        this.state.selectedProcedure
                      )) {
                        const selectedPro = this.state.selectedProcedure;
                        if (this.state.selectedTeeth.length === 0) {
                          const pro = new Procedures({
                            id: key + "-" + new Date().getTime(),
                            slectedGraphicCode: [],
                            name: selectedPro[key].value,
                            quantity: selectedPro[key].quantity,
                            patientid: this.props.patient._id,
                            tooth: [] as number[],
                            fees:
                              selectedPro[key].price ||
                              selectedPro[key].defaultPrice,
                            done: false,
                            date: new Date().toISOString()
                          });
                          procedures.push(pro);
                        } else {
                          if (this.state.saveProcedureSeparate) {
                            this.state.selectedTeeth.map(item => {
                              const slectedGraphicCode = this.props.patient.procedureGraphicCode.filter(
                                code => {
                                  return code.includes(item.toString()) &&
                                    code.includes(key.split("-")[0])
                                    ? true
                                    : false;
                                }
                              );

                              const pro = new Procedures({
                                id:
                                  key + "-" + item + "-" + new Date().getTime(),
                                slectedGraphicCode: slectedGraphicCode,
                                name: selectedPro[key].value,
                                quantity: selectedPro[key].quantity,
                                patientid: this.props.patient._id,
                                tooth: [item],
                                fees:
                                  selectedPro[key].price ||
                                  selectedPro[key].defaultPrice,
                                done: false,
                                date: new Date().toISOString()
                              });
                              procedures.push(pro);
                            });
                          } else {
                            const slectedGraphicCode: string[] = [];
                            this.state.selectedTeeth.map(item => {
                              this.props.patient.procedureGraphicCode.map(
                                code => {
                                  if (
                                    code.includes(item.toString()) &&
                                    code.includes(key.split("-")[0])
                                  ) {
                                    slectedGraphicCode.push(code);
                                  }
                                }
                              );
                            });
                            const pro = new Procedures({
                              id: key + "-" + new Date().getTime(),
                              slectedGraphicCode: slectedGraphicCode,
                              name: selectedPro[key].value,
                              quantity: selectedPro[key].quantity,
                              patientid: this.props.patient._id,
                              tooth: this.state.selectedTeeth,
                              fees:
                                selectedPro[key].price ||
                                selectedPro[key].defaultPrice,
                              done: false,
                              date: new Date().toISOString()
                            });
                            procedures.push(pro);
                          }
                        }
                      }
                      this.props.patient.procedures = [
                        ...this.props.patient.procedures,
                        ...procedures
                      ];
                      this.setState(
                        {
                          showProcedure: false,
                          currentProcedureIndex: 0,
                          selectedProcedure: {},
                          selectedTeeth: [],
                          saveProcedureSeparate: true
                        },
                        this.props.toggleProcedureTable
                      );
                    }
                  }}
                >
                  Add procedures (
                  {Object.keys(this.state.selectedProcedure).length})
                </button>
              </BTCol>
            </BTRow>
          </div>
        )}
      </div>
    );
  }

  mapQuadrant(min: number, max: number, reverse: boolean) {
    let arr = this.props.patient.teeth;
    arr = arr.filter(tooth => tooth.ISO >= min && tooth.ISO <= max);
    arr = reverse ? arr.reverse() : arr;
    return arr.map(tooth => (
      <td
        key={"tooth" + tooth.ISO}
        style={{ background: conditionToColor(tooth.condition) }}
        onClick={() => (this.viewToothISO = tooth.ISO)}
      >
        <span
          className="has-notes"
          style={tooth.notes.length ? {} : { display: "none" }}
        />
        {tooth.ISO}
      </td>
    ));
  }
}
