export default function Footer() {
    return (
        <footer className="footer sm:footer-horizontal bg-neutral text-neutral-content grid-rows-2 p-10">
            <nav>
                <h6 className="footer-title">Services</h6>
                <a className="link link-hover">Hospitals</a>
                <a className="link link-hover">Documents</a>
                <a className="link link-hover">Scanning</a>
            </nav>
            <nav>
                <h6 className="footer-title">Company</h6>
                <a className="link link-hover">About us</a>
                <a className="link link-hover">Contact</a>
                <a className="link link-hover">other</a>
            </nav>
            <nav>
                <h6 className="footer-title">Legal</h6>
                <a className="link link-hover">Terms of use</a>
                <a className="link link-hover">Privacy policy</a>
                <a className="link link-hover">Cookie policy</a>
            </nav>
            <nav>
                <h6 className="footer-title">Social</h6>
                <a className="link link-hover">Twitter</a>
                <a className="link link-hover">Instagram</a>
                <a className="link link-hover">Facebook</a>
            </nav>
            <nav>
                <h6 className="footer-title">Explore</h6>
                <a className="link link-hover">AI model</a>
                <a className="link link-hover">Security</a>
                <a className="link link-hover">Pricing</a>
            </nav>
            <nav>
                <h6 className="footer-title">Apps</h6>
                <a className="link link-hover">IOS</a>  
                <a className="link link-hover">Android</a>
            </nav>
        </footer>
    );
}
