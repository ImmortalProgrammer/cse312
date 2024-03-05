import Main from "./Component/Main";
import "./styles.css";
// import Chat from "./Chat";
// import SideBar from "./Component/SideBar";

export default function App() {
  return (
    <div className="App">
      {/* <div className="grid grid-cols-[300px_minmax(900px,_1fr)_100px]">
        <SideBar />
        <Chat className="col-span-2 " />
      </div> */}
      <Main />
    </div>
  );
}
